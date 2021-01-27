/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/
// SPDX-License-Identifier: GPL-3.0

#include <libsolutil/LP.h>

#include <libsolutil/CommonData.h>
#include <libsolutil/StringUtils.h>
#include <liblangutil/Exceptions.h>

#include <range/v3/view/enumerate.hpp>
#include <range/v3/view/transform.hpp>
#include <range/v3/view/filter.hpp>
#include <range/v3/view/tail.hpp>
#include <range/v3/view/iota.hpp>
#include <range/v3/algorithm/all_of.hpp>
#include <range/v3/algorithm/any_of.hpp>
#include <range/v3/algorithm/max.hpp>
#include <range/v3/algorithm/count_if.hpp>
#include <range/v3/iterator/operations.hpp>

#include <boost/range/algorithm_ext/erase.hpp>

using namespace std;
using namespace solidity;
using namespace solidity::util;
using namespace solidity::smtutil;

using rational = boost::rational<bigint>;


namespace
{

string toString(rational const& _value, size_t _paddedLength = 2)
{
	string result;
	if (_value == rational(bigint(1) << 256))
		result = "2**256";
	else if (_value == rational(bigint(1) << 256) - 1)
		result = "2**256-1";
	else if (_value.denominator() == bigint(1))
		result = _value.numerator().str();
	else
		result = to_string(_value);
	if (result.length() < _paddedLength)
		result = string(_paddedLength - result.length(), ' ') + result;
	return result;
}


vector<rational> factorForVariable(size_t _index, rational _factor)
{
	vector<rational> result(_index + 1);
	result[_index] = move(_factor);
	return result;
}

rational get(vector<rational> const& _data, size_t _index)
{
	return _index < _data.size() ? _data[_index] : 0;
}

template <class T>
void resizeAndSet(vector<T>& _data, size_t _index, T _value)
{
	if (_data.size() <= _index)
		_data.resize(_index + 1);
	_data[_index] = move(_value);
}

vector<rational>& operator/=(vector<rational>& _data, rational const& _divisor)
{
	for (rational& x: _data)
		if (x.numerator())
			x /= _divisor;
	return _data;
}

vector<rational>& operator*=(vector<rational>& _data, rational const& _factor)
{
	for (rational& x: _data)
		if (x.numerator())
			x *= _factor;
	return _data;
}

vector<rational> operator*(rational const& _factor, vector<rational> _data)
{
	for (rational& x: _data)
		if (x.numerator())
			x *= _factor;
	return _data;
}

vector<rational> operator-(vector<rational> const& _x, vector<rational> const& _y)
{
	vector<rational> result;
	for (size_t i = 0; i < max(_x.size(), _y.size()); ++i)
		result.emplace_back(get(_x, i) - get(_y, i));
	return result;
}

vector<rational>& operator-=(vector<rational>& _x, vector<rational> const& _y)
{
	solAssert(_x.size() == _y.size(), "");
	for (size_t i = 0; i < _x.size(); ++i)
		_x[i] -= _y[i];
	return _x;
}

vector<rational> add(vector<rational> const& _x, vector<rational> const& _y)
{
	vector<rational> result;
	for (size_t i = 0; i < max(_x.size(), _y.size()); ++i)
		result.emplace_back(get(_x, i) + get(_y, i));
	return result;
}

bool isConstant(vector<rational> const& _x)
{
	return ranges::all_of(_x | ranges::views::tail, [](rational const& _v) { return _v == 0; });
}

/// Multiply two vectors where the first element of each vector is a constant factor.
/// Only works if at most one of the vector has a nonzero element after the first.
/// If this condition is violated, returns nullopt.
optional<vector<rational>> vectorProduct(optional<vector<rational>> _x, optional<vector<rational>> _y)
{
	if (!_x || !_y)
		return std::nullopt;
	if (!isConstant(*_y))
		swap(_x, _y);
	if (!isConstant(*_y))
		return std::nullopt;

	rational factor = _y->front();

	for (rational& element: *_x)
		element *= factor;
	return *_x;
}


/**
 * Simplex tableau with the first row representing the objective function.
 */
struct Tableau
{
	std::vector<std::vector<rational>> data;
};


pair<vector<Constraint>, bool> toEquationalForm(vector<Constraint> _constraints)
{
	size_t varsNeeded = static_cast<size_t>(ranges::count_if(_constraints, [](Constraint const& _c) { return !_c.equality; }));

	vector<Constraint> result;

	size_t columns = _constraints.at(0).data.size();
	size_t currentVariable = 0;
	for (Constraint& constraint: _constraints)
	{
		solAssert(constraint.data.size() == columns, "");
		result.emplace_back(Constraint{move(constraint.data) + vector<rational>(varsNeeded, rational{}), true});
		if (!constraint.equality)
		{
			result.back().data[columns + currentVariable] = bigint(1);
			currentVariable++;
		}
	}

	return make_pair(move(result), varsNeeded > 0);
}

optional<size_t> findPivotColumn(Tableau const& _tableau)
{
	auto&& [maxColumn, maxValue] = ranges::max(
		_tableau.data[0] | ranges::views::enumerate | ranges::views::tail,
		{},
		[](std::pair<size_t, rational> const& _x) { return _x.second; }
	);

	if (maxValue <= rational{0})
		return nullopt; // found optimum
	else
		return maxColumn;
}

optional<size_t> findPivotRow(Tableau const& _tableau, size_t _pivotColumn)
{
	auto positiveColumnEntries =
		ranges::views::iota(size_t(1), _tableau.data.size()) |
		ranges::views::transform([&](size_t i) {
			return make_pair(i, _tableau.data[i][_pivotColumn]);
		}) |
		ranges::views::filter([](pair<size_t, rational> const& _entry) {
			return _entry.second > 0;
		});
	if (positiveColumnEntries.empty())
		return nullopt; // unbounded

	return ranges::min(
		positiveColumnEntries,
		{},
		[&](std::pair<size_t, rational> const& _entry) {
			return _tableau.data[_entry.first][0] / _entry.second;
		}
	).first;
}

void performPivot(Tableau& _tableau, size_t _pivotRow, size_t _pivotColumn)
{
	rational pivot = _tableau.data[_pivotRow][_pivotColumn];
	solAssert(pivot != 0, "");
	if (pivot != 1)
		_tableau.data[_pivotRow] /= pivot;
	solAssert(_tableau.data[_pivotRow][_pivotColumn] == rational(1), "");

	for (size_t i = 0; i < _tableau.data.size(); ++i)
		if (i != _pivotRow)
		{
			if (_tableau.data[i][_pivotColumn] == rational{})
			{
			}
			else if (_tableau.data[i][_pivotColumn] == rational{1})
				_tableau.data[i] -= _tableau.data[_pivotRow];
			else
				_tableau.data[i] -= _tableau.data[i][_pivotColumn] * _tableau.data[_pivotRow];
		}
}

/*
void printVector(vector<rational> const& _v)
{
	for (auto const& element: _v)
		cout << toString(element, 3) << ", ";
	cout << endl;
}
*/
vector<rational> optimalVector(Tableau const& _tableau);

/*
void printTableau(Tableau _tableau)
{
	cout << "------------" << endl;
	for (auto const& row: _tableau.data)
		printVector(row);
	cout << "------------" << endl;
	cout << "Solution: ";
	printVector(optimalVector(_tableau));
}
*/

string toString(SolvingState const& _state)
{
	string result;

	for (Constraint const& constraint: _state.constraints)
	{
		vector<string> line;
		for (auto&& [index, multiplier]: constraint.data | ranges::views::enumerate)
			if (index > 0 && multiplier != 0)
			{
				string mult =
					multiplier == -1 ?
					"-" :
					multiplier == 1 ?
					"" :
					toString(multiplier) + " ";
				line.emplace_back(mult + _state.variableNames.at(index));
			}
		result += joinHumanReadable(line, " + ") + (constraint.equality ? "  = " : " <= ") + toString(constraint.data.front()) + "\n";
	}
	result += "Bounds:\n";
	for (auto&& [index, bounds]: _state.bounds | ranges::view::enumerate)
	{
		if (!bounds[0] && !bounds[1])
			continue;
		if (bounds[0])
			result += toString(*bounds[0]) + " <= ";
		result += _state.variableNames.at(index);
		if (bounds[1])
			result += " <= " + toString(*bounds[1]);
		result += "\n";
	}
	return result;
}

void selectLastVectorsAsBasis(Tableau& _tableau)
{
	// We might skip the operation for a column if it is already the correct
	// unit vector and its cost coefficient is zero.
	size_t columns = _tableau.data.at(0).size();
	size_t rows = _tableau.data.size();
	for (size_t i = 1; i < rows; ++i)
		performPivot(_tableau, i, columns - rows + i);
}

/// Returns the row containing 1 if all other rows are zero.
optional<size_t> basisVariable(Tableau const& _tableau, size_t _column)
{
	optional<size_t> row;
	for (size_t i = 1; i < _tableau.data.size(); ++i)
		if (_tableau.data[i][_column] == bigint(1))
		{
			if (row)
				return std::nullopt;
			else
				row = i;
		}
		else if (_tableau.data[i][_column] != 0)
			return std::nullopt;
	return row;
}

vector<rational> optimalVector(Tableau const& _tableau)
{
	vector<rational> result;
	set<size_t> rowsSeen;
	for (size_t j = 1; j < _tableau.data[0].size(); j++)
	{
		optional<size_t> row = basisVariable(_tableau, j);
		if (row && rowsSeen.count(*row))
			row = nullopt;
		result.emplace_back(row ? _tableau.data[*row][0] : rational{});
		if (row)
			rowsSeen.insert(*row);
	}
	//solAssert(rowsSeen.size() == _tableau.data.size() - 1, "");
	return result;
}


enum class LPResult
{
	Unknown,
	Unbounded,
	Feasible,
	Infeasible
};

/// Solve the LP Ax = b s.t. min c^Tx
/// The first row encodes the objective function
/// The first column encodes b
/// Assumes the tableau has a trivial basic feasible solution.
pair<LPResult, Tableau> simplexEq(Tableau _tableau)
{
	size_t iterations = 50 + _tableau.data[0].size() * 2;
	if (iterations > 60)
		iterations = 60;
	for (size_t step = 0; step <= iterations; ++step)
	{
		optional<size_t> pivotColumn = findPivotColumn(_tableau);
		if (!pivotColumn)
		{
			////cout << "Optimum: ";
			//vector<rational> optimum = optimalVector(_tableau);
			//printVector(optimum);

			cout << "Feasible after " << step << " steps." << endl;
			cout << "Constraints: " << (_tableau.data.size() - 1) << endl;
			cout << "Variables: " << (_tableau.data[0].size() - 1) << endl;
			return make_pair(LPResult::Feasible, move(_tableau));
		}
		////cout << "Pivot column: " << *pivotColumn << endl;
		optional<size_t> pivotRow = findPivotRow(_tableau, *pivotColumn);
		if (!pivotRow)
		{
			////cout << "unbounded" << endl;
			return make_pair(LPResult::Unbounded, move(_tableau));
		}
		////cout << "Pivot row: " << *pivotRow << endl;
		performPivot(_tableau, *pivotRow, *pivotColumn);
		////cout << "After step " << step << endl;
		//printTableau(_tableau);
	}
	cout << "LP: Too many iterations: " << iterations << endl;
	return make_pair(LPResult::Unknown, Tableau{});
}

pair<LPResult, Tableau> simplexPhaseI(Tableau _tableau)
{
	vector<rational> originalObjective = _tableau.data[0];

	size_t rows = _tableau.data.size();
	size_t columns = _tableau.data.at(0).size();
	for (size_t i = 1; i < rows; ++i)
	{
		if (_tableau.data[i][0] < 0)
			_tableau.data[i] *= -1;
		_tableau.data[i] += vector<bigint>(rows - 1, bigint{});
		_tableau.data[i][columns + i - 1] = 1;
	}
	_tableau.data[0] =
		vector<rational>(columns, rational{}) +
		vector<rational>(rows - 1, rational{-1});

	////cout << "Phase I tableau: " << endl;
	//printTableau(_tableau);

	selectLastVectorsAsBasis(_tableau);

	////cout << "After basis selection: " << endl;
	//printTableau(_tableau);

	LPResult result;
	tie(result, _tableau) = simplexEq(move(_tableau));

	// TODO This should actually not happen.
	if (result != LPResult::Feasible && result != LPResult::Unbounded)
	{
		//cout << "Unknown because phaseI resulted in " << static_cast<int>(result) << endl;
		return make_pair(LPResult::Unknown, Tableau{});
	}
	vector<rational> optimum = optimalVector(_tableau);
	////cout << "PhaseI solution: ";
	//printVector(optimum);

	for (size_t i = columns - 1; i < optimum.size(); ++i)
		if (optimum[i] != 0)
			return make_pair(LPResult::Infeasible, Tableau{});

	_tableau.data[0] = originalObjective;
	for (size_t i = 1; i < rows; ++i)
		_tableau.data[i].resize(columns);

	////cout << "Tableau after Phase I: " << endl;
	//printTableau(_tableau);

	// TODO do we need to select a basis?
	//_tableau = selectLastVectorsAsBasis(move(_tableau));
	////cout << "After basis correction: " << endl;
	//printTableau(_tableau);

	return make_pair(LPResult::Feasible, move(_tableau));
}

bool needsPhaseI(Tableau const& _tableau)
{
	// TODO with equality constraints, this may need refinement.
	for (size_t i = 1; i < _tableau.data.size(); ++i)
		if (_tableau.data[i][0] < 0)
			return true;
	return false;
}

/// Solve the LP Ax <= b s.t. min c^Tx
/// The first row encodes the objective function
/// The first column encodes b
pair<LPResult, vector<rational>> simplex(vector<Constraint> _constraints, vector<rational> _objectives)
{
	Tableau tableau;
	tableau.data.emplace_back(move(_objectives));
	bool hasEquations = false;
	tie(_constraints, hasEquations) = toEquationalForm(_constraints);
	for (Constraint& c: _constraints)
		tableau.data.emplace_back(move(c.data));
	tableau.data.front().resize(tableau.data.at(1).size());
	//cout << "Equational: " << endl;
	//printTableau(tableau);
	if (hasEquations || needsPhaseI(tableau))
	{
		LPResult result;
		tie(result, tableau) = simplexPhaseI(move(tableau));
		if (result == LPResult::Infeasible || result == LPResult::Unknown)
			return make_pair(result, vector<rational>{});
		solAssert(result == LPResult::Feasible, "");
	}
	return make_pair(LPResult::Unknown, vector<rational>{});
	LPResult result;
	vector<rational> optimum;
	tie(result, tableau) = simplexEq(move(tableau));
	if (result == LPResult::Feasible || result == LPResult::Unbounded)
	{
		optimum = optimalVector(tableau);
		////cout << "Solution: " << endl;
		//printVector(optimum);
	}
	return make_pair(result, move(optimum));
}

bool boundsToConstraints(SolvingState& _state)
{
	size_t columns = _state.variableNames.size();

	// Turn bounds into constraints.
	for (auto const& [index, bounds]: _state.bounds | ranges::views::enumerate | ranges::views::tail)
	{
		if (bounds[0] && bounds[1])
		{
			if (*bounds[0] > *bounds[1])
				return false;
			if (*bounds[0] == *bounds[1])
			{
				vector<rational> c(columns);
				c[0] = *bounds[0];
				c[index] = bigint(1);
				_state.constraints.emplace_back(Constraint{move(c), true});
				continue;
			}
		}
		if (bounds[0] && *bounds[0] > 0)
		{
			vector<rational> c(columns);
			c[0] = -*bounds[0];
			c[index] = bigint(-1);
			_state.constraints.emplace_back(Constraint{move(c), false});
		}
		if (bounds[1])
		{
			vector<rational> c(columns);
			c[0] = *bounds[1];
			c[index] = bigint(1);
			_state.constraints.emplace_back(Constraint{move(c), false});
		}
	}
	_state.bounds.clear();
	return true;
}

template <class T>
void eraseIndices(vector<T>& _data, set<size_t> const& _indices)
{
	// TODO make this more efficient.
	vector<T> result;
	for (size_t i = 0; i < _data.size(); i++)
		if (!_indices.count(i))
			result.emplace_back(move(_data[i]));
	_data = move(result);
}


void removeColumns(SolvingState& _state, set<size_t> const& _columnsToRemove)
{
	eraseIndices(_state.bounds, _columnsToRemove);
	for (Constraint& constraint: _state.constraints)
		eraseIndices(constraint.data, _columnsToRemove);
	eraseIndices(_state.variableNames, _columnsToRemove);
}


bool extractDirectConstraints(SolvingState& _state, bool& _changed)
{
	// Turn constraints of the form ax <= b into an upper bound on x.
	set<size_t> constraintsToRemove;
	for (auto const& [index, constraint]: _state.constraints | ranges::views::enumerate)
	{
		auto nonzero = constraint.data | ranges::views::enumerate | ranges::views::tail | ranges::view::filter(
			[](std::pair<size_t, rational> const& _x) { return _x.second != 0; }
		);
		// TODO we can exit early on in the loop above.
		if (ranges::distance(nonzero) > 1)
			continue;
		constraintsToRemove.insert(index);
		if (ranges::distance(nonzero) == 0)
		{
			// 0 <= b or 0 = b
			if (
				constraint.data.front() < 0 ||
				(constraint.equality && constraint.data.front() != 0)
			)
				return false; // Infeasible.
		}
		else
		{
			auto&& [varIndex, factor] = nonzero.front();
			// a * x <= b
			rational bound = constraint.data[0] / factor;
			if (
				(factor >= 0 || constraint.equality) &&
				(!_state.bounds[varIndex][1] || bound < _state.bounds[varIndex][1])
			)
				_state.bounds[varIndex][1] = bound;
			if (
				(factor <= 0 || constraint.equality) &&
				(!_state.bounds[varIndex][0] || bound > _state.bounds[varIndex][0])
			)
				// Lower bound must be at least zero.
				_state.bounds[varIndex][0] = max(rational{}, bound);
		}
	}
	if (!constraintsToRemove.empty())
	{
		_changed = true;
		eraseIndices(_state.constraints, constraintsToRemove);
	}
	return true;
}

bool removeFixedVariables(SolvingState& _state, bool& _changed)
{
	set<size_t> variablesToRemove;
	// Remove variables that have equal lower and upper bound.
	for (auto const& [index, bounds]: _state.bounds | ranges::views::enumerate)
	{
		if (!bounds[1])
			continue;
		// Lower bound must be at least zero.
		rational lower = max(rational{}, bounds[0] ? *bounds[0] : rational{});
		rational upper = *bounds[1];
		if (upper < lower)
			return false; // Infeasible.
		if (upper != lower)
			continue;
		////cout << "Removing variable " << _state.variableNames[index] << endl;
		for (Constraint& constraint: _state.constraints)
		{
			if (constraint.data.at(index) != 0)
			{
				constraint.data[0] -= constraint.data[index] * lower;
				constraint.data[index] = 0;
			}
			variablesToRemove.insert(index);
		}
	}

	if (!variablesToRemove.empty())
	{
		_changed = true;
		removeColumns(_state, variablesToRemove);
	}
	return true;
}

bool removeEmptyColumns(SolvingState& _state, bool& _changed)
{
	vector<bool> variablesSeen(_state.bounds.size(), false);
	for (auto const& constraint: _state.constraints)
	{
		for (auto&& [index, factor]: constraint.data | ranges::views::enumerate | ranges::views::tail)
			if (factor)
				variablesSeen[index] = true;
	}

	// TODO we could assert that any variable we remove does not have conflicting bounds.

	set<size_t> variablesToRemove;
	for (auto&& [i, seen]: variablesSeen | ranges::views::enumerate | ranges::views::tail)
		if (!seen)
			variablesToRemove.insert(i);
	if (!variablesToRemove.empty())
	{
		_changed = true;
		removeColumns(_state, variablesToRemove);
	}
	return true;
}

auto nonZeroEntriesInColumn(SolvingState& _state, size_t _column)
{
	return
		_state.constraints |
		ranges::views::enumerate |
		ranges::views::filter([=](auto const& _entry) { return _entry.second.data[_column] != 0; }) |
		ranges::views::transform([](auto const& _entry) { return _entry.first; });
}

pair<vector<bool>, vector<bool>> firstConnectedComponent(SolvingState& _state)
{
	solAssert(_state.variableNames.size() >= 2, "");

	vector<bool> includedColumns(_state.variableNames.size(), false);
	vector<bool> includedRows(_state.constraints.size(), false);
	stack<size_t> columnsToProcess;
	columnsToProcess.push(1);
	while (!columnsToProcess.empty())
	{
		size_t column = columnsToProcess.top();
		columnsToProcess.pop();
		if (includedColumns[column])
			continue;
		includedColumns[column] = true;

		for (size_t row: nonZeroEntriesInColumn(_state, column))
		{
			if (includedRows[row])
				continue;
			includedRows[row] = true;
			for (auto const& [index, entry]: _state.constraints[row].data | ranges::view::enumerate | ranges::views::tail)
				if (entry && !includedColumns[index])
					columnsToProcess.push(index);
		}
	}
	return make_pair(move(includedColumns), move(includedRows));
}

SolvingState splitProblem(SolvingState& _state)
{
	vector<bool> includedColumns;
	vector<bool> includedRows;
	tie(includedColumns, includedRows) = firstConnectedComponent(_state);
	// "+ 1" because the constant column is included implicitly.
	size_t columnCount = static_cast<size_t>(ranges::count_if(includedColumns, ranges::identity{})) + 1;
	cout << "Splitting off " << (columnCount - 1) << " of " << (_state.variableNames.size() - 1) << " variables." << endl;
	SolvingState splitOff;
	if (columnCount == _state.variableNames.size())
	{
		splitOff = move(_state);
		_state = SolvingState();
	}
	else
	{
		splitOff.variableNames.emplace_back();
		splitOff.bounds.emplace_back();

		set<size_t> variablesToRemove;
		for (auto&& [i, included]: includedColumns | ranges::views::enumerate | ranges::views::tail)
		{
			if (!included)
				continue;
			variablesToRemove.insert(i);
			splitOff.variableNames.emplace_back(move(_state.variableNames[i]));
			splitOff.bounds.emplace_back(move(_state.bounds[i]));
		}
		set<size_t> rowsToRemove;
		for (auto&& [i, included]: includedRows | ranges::views::enumerate)
		{
			if (!included)
				continue;
			rowsToRemove.insert(i);
			Constraint splitRow{{}, _state.constraints[i].equality};
			for (size_t j = 0; j < _state.constraints[i].data.size(); j++)
				if (j == 0 || includedColumns[j])
					splitRow.data.push_back(_state.constraints[i].data[j]);
			splitOff.constraints.push_back(move(splitRow));
		}
		removeColumns(_state, variablesToRemove);
		eraseIndices(_state.constraints, rowsToRemove);
	}
	return splitOff;
}

bool simplifySolvingState(SolvingState& _state)
{
	// - Constraints with exactly one nonzero coefficient represent "a x <= b"
	//   and thus are turned into bounds.
	// - Constraints with zero nonzero coefficients are constant relations.
	//   If such a relation is false, answer "infeasible", otherwise remove the constraint.
	// - Empty columns can be removed.
	// - Variables with matching bounds can be removed from the problem by substitution.

	bool changed = true;
	while (changed)
	{
		changed = false;

		if (!extractDirectConstraints(_state, changed))
			return false;

		if (!removeFixedVariables(_state, changed))
			return false;

		if (!removeEmptyColumns(_state, changed))
			return false;
	}

	// TODO return the values selected for named variables in order to
	// be used when returning the model.
	return true;
}

void normalizeRowLengths(SolvingState& _state)
{
	size_t vars = max(_state.variableNames.size(), _state.bounds.size());
	for (Constraint const& c: _state.constraints)
		vars = max(vars, c.data.size());
	_state.variableNames.resize(vars);
	_state.bounds.resize(vars);
	for (Constraint& c: _state.constraints)
		c.data.resize(vars);
}

}

void LPSolver::reset()
{
	m_state = stack<State>{{State{}}};
}

void LPSolver::push()
{
	m_state.push(m_state.top());
}

void LPSolver::pop()
{
	m_state.pop();
	solAssert(!m_state.empty(), "");
}

void LPSolver::declareVariable(string const& _name, SortPointer const& _sort)
{
	// TODO This will not be an integer variable in our model.
	// Introduce a new kind?
	solAssert(_sort && _sort->kind == Kind::Int, "");
	solAssert(!m_state.top().variables.count(_name), "");
	size_t index = m_state.top().variables.size() + 1;
	m_state.top().variables[_name] = index;
}

void LPSolver::addAssertion(Expression const& _expr)
{
	if (_expr.name == "and")
	{
		addAssertion(_expr.arguments.at(0));
		addAssertion(_expr.arguments.at(1));
	}
	else if (_expr.name == "<=" || _expr.name == "=")
	{
		optional<vector<rational>> left = parseLinearSum(_expr.arguments.at(0));
		optional<vector<rational>> right = parseLinearSum(_expr.arguments.at(1));
		if (!left || !right)
			return;

		// TODO we could do bounds computations earlier on.
		vector<rational> data = *left - *right;
		data[0] *= -1;
		m_state.top().constraints.emplace_back(Constraint{move(data), _expr.name == "="});
	}
	else if (_expr.name == ">=")
		addAssertion(_expr.arguments.at(1) <= _expr.arguments.at(0));
	else if (_expr.name == "<")
		addAssertion(_expr.arguments.at(0) <= _expr.arguments.at(1) - 1);
	else if (_expr.name == ">")
		addAssertion(_expr.arguments.at(1) < _expr.arguments.at(0));
}

pair<CheckResult, vector<string>> LPSolver::check(vector<Expression> const& /*_expressionsToEvaluate*/)
{
	SolvingState state;
	for (auto&& [name, index]: m_state.top().variables)
		resizeAndSet(state.variableNames, index, name);
	for (auto&& [index, bound]: m_state.top().bounds)
		resizeAndSet(state.bounds, index, bound);
	state.constraints = m_state.top().constraints;
	normalizeRowLengths(state);

	cout << endl;
	cout << "----------------------------------------" << endl;
	cout << "Solving LP:\n" << toString(state) << endl;
	if (!simplifySolvingState(state))
	{
		//cout << "LP: infeasible." << endl;
		return make_pair(CheckResult::UNSATISFIABLE, vector<string>{});
	}
	cout << "Simplified to:\n" << toString(state) << endl;
	cout << "----------------------------------------" << endl;

	while (!state.constraints.empty())
	{
		SolvingState split = splitProblem(state);
		solAssert(!split.constraints.empty(), "");
		solAssert(split.variableNames.size() >= 2, "");
		cout << "Split off:\n" << toString(split) << endl;
		cout << "----------------------------------------" << endl;
		if (!boundsToConstraints(split))
			return make_pair(CheckResult::UNSATISFIABLE, vector<string>{});

		LPResult lpResult;
		vector<rational> solution;
		tie(lpResult, solution) = simplex(split.constraints, vector<rational>(1, rational(bigint(0))) + vector<rational>(split.constraints.front().data.size() - 1, rational(bigint(1))));
		switch (lpResult)
		{
		case LPResult::Feasible:
		case LPResult::Unbounded:
			break;
		case LPResult::Infeasible:
			return make_pair(CheckResult::UNSATISFIABLE, vector<string>{});
		case LPResult::Unknown:
			return make_pair(CheckResult::UNKNOWN, vector<string>{});
			break;
		}
	}
	cout << "No more sub-problems to split off." << endl;
	cout << "----------------------------------------" << endl;

	bool solveInteger = false;

	//cout << "LP: feasible / unbounded, because no constraints left." << endl;
	if (solveInteger)
		return make_pair(CheckResult::UNKNOWN, vector<string>{});
	else
		// TODO evaluated model based on removed variables
		return make_pair(CheckResult::SATISFIABLE, vector<string>{});

#if 0
	LPResult lpResult;
	vector<rational> solution;
	tie(lpResult, solution) = simplex(state.constraints, vector<rational>(1, rational(bigint(0))) + vector<rational>(state.constraints.front().data.size() - 1, rational(bigint(1))));

	vector<string> model;
	for (Expression const& e: _expressionsToEvaluate)
	{
		if (e.arguments.empty() && m_state.top().variables.count(e.name))
		{
			size_t index = m_state.top().variables.at(e.name);
			solAssert(index > 0, "");
			model.emplace_back(toString(solution.at(index - 1), 0));
		}
		else
		{
			model = {};
			break;
		}
	}
	return make_pair(smtResult, move(model));
#endif
}

optional<vector<rational>> LPSolver::parseLinearSum(smtutil::Expression const& _expr) const
{
	if (_expr.arguments.empty() || _expr.name == "*")
		return parseProduct(_expr);
	else if (_expr.name == "+" || _expr.name == "-")
	{
		optional<vector<rational>> left = parseLinearSum(_expr.arguments.at(0));
		optional<vector<rational>> right = parseLinearSum(_expr.arguments.at(1));
		if (!left || !right)
			return std::nullopt;
		return _expr.name == "+" ? add(*left, *right) : *left - *right;
	}
	else
		return std::nullopt;
}

optional<vector<rational>> LPSolver::parseProduct(smtutil::Expression const& _expr) const
{
	if (_expr.arguments.empty())
		return parseFactor(_expr);
	else if (_expr.name == "*")
		// The multiplication ensures that only one of them can be a variable.
		return vectorProduct(parseFactor(_expr.arguments.at(0)), parseFactor(_expr.arguments.at(1)));
	else
		return std::nullopt;
}

optional<vector<rational>> LPSolver::parseFactor(smtutil::Expression const& _expr) const
{
	solAssert(_expr.arguments.empty(), "");
	solAssert(!_expr.name.empty(), "");
	if ('0' <= _expr.name[0] && _expr.name[0] <= '9')
		return vector<rational>{rational(bigint(_expr.name))};
	else if (_expr.name == "true")
		return vector<rational>{rational(bigint(1))};
	else if (_expr.name == "false")
		return vector<rational>{rational(bigint(0))};

	size_t index = m_state.top().variables.at(_expr.name);
	solAssert(index > 0, "");
	return factorForVariable(index, rational(bigint(1)));
}

void LPSolver::addUpperBound(size_t _index, rational _value)
{
	//cout << "adding " << variableName(_index) << " <= " << toString(_value) << endl;
	if (!m_state.top().bounds[_index][1] || _value < *m_state.top().bounds[_index][1])
		m_state.top().bounds[_index][1] = move(_value);
}

void LPSolver::addLowerBound(size_t _index, rational _value)
{
	//cout << "adding " << variableName(_index) << " >= " << toString(_value) << endl;
	if (!m_state.top().bounds[_index][0] || _value > *m_state.top().bounds[_index][0])
		m_state.top().bounds[_index][0] = move(_value);
}


string LPSolver::variableName(size_t _index) const
{
	for (auto const& v: m_state.top().variables)
		if (v.second == _index)
			return v.first;
	return {};
}
