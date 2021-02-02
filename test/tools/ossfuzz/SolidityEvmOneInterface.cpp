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

#include <test/tools/ossfuzz/SolidityEvmOneInterface.h>

#include <liblangutil/Exceptions.h>
#include <liblangutil/SourceReferenceFormatter.h>

using namespace solidity::test::fuzzer;

SolidityCompilationFramework::SolidityCompilationFramework(langutil::EVMVersion _evmVersion)
{
	m_evmVersion = _evmVersion;
}

solidity::bytes SolidityCompilationFramework::compileContract(
	std::string const& _sourceCode,
	std::string const& _contractName,
	std::map<std::string, solidity::util::h160> const& _libraryAddresses,
	frontend::OptimiserSettings _optimization
)
{
	std::string sourceCode = _sourceCode;
	m_compiler.setSources({{"", sourceCode}});
	m_compiler.setLibraries(_libraryAddresses);
	m_compiler.setEVMVersion(m_evmVersion);
	m_compiler.setOptimiserSettings(_optimization);
	if (!m_compiler.compile())
	{
		langutil::SourceReferenceFormatter formatter(std::cerr, false, false);

		for (auto const& error: m_compiler.errors())
			formatter.printExceptionInformation(
					*error,
					formatter.formatErrorInformation(*error)
			);
		std::cerr << "Compiling contract failed" << std::endl;
	}
	evmasm::LinkerObject obj = m_compiler.object(
		_contractName.empty() ?
		m_compiler.lastContractName() :
		_contractName
	);
	return obj.bytecode;
}

bool EVMOneUtility::isOutputExpected(
	uint8_t const* _result,
	size_t _length,
	std::vector<uint8_t> const& _expectedOutput
)
{
	if (_length != _expectedOutput.size())
		return false;

	return (memcmp(_result, _expectedOutput.data(), _length) == 0);
}

evmc_message EVMOneUtility::initializeMessage(bytes const& _input)
{
	// Zero initialize all message fields
	evmc_message msg = {};
	// Gas available (value of type int64_t) is set to its maximum
	// value.
	msg.gas = std::numeric_limits<int64_t>::max();
	msg.input_data = _input.data();
	msg.input_size = _input.size();
	return msg;
}

evmc::result EVMOneUtility::executeContract(
	EVMHost& _hostContext,
	bytes const& _functionHash,
	evmc_address _deployedAddress
)
{
	evmc_message message = initializeMessage(_functionHash);
	message.destination = _deployedAddress;
	message.kind = EVMC_CALL;
	return _hostContext.call(message);
}

evmc::result EVMOneUtility::deployContract(EVMHost& _hostContext, bytes const& _code)
{
	evmc_message message = initializeMessage(_code);
	message.kind = EVMC_CREATE;
	return _hostContext.call(message);
}

evmc::result EVMOneUtility::deployAndExecute(EVMHost& _hostContext, bytes _byteCode, std::string _hexEncodedInput)
{
	// Deploy contract and signal failure if deploy failed
	evmc::result createResult = deployContract(_hostContext, _byteCode);
	solAssert(
		createResult.status_code == EVMC_SUCCESS,
		"Proto solc fuzzer: Contract creation failed"
	);

	// Execute test function and signal failure if EVM reverted or
	// did not return expected output on successful execution.
	evmc::result callResult = executeContract(
		_hostContext,
		util::fromHex(_hexEncodedInput),
		createResult.create_address
	);

	// We don't care about EVM One failures other than EVMC_REVERT
	solAssert(callResult.status_code != EVMC_REVERT, "Proto solc fuzzer: EVM One reverted");
	return callResult;
}

evmc::result EVMOneUtility::compileDeployAndExecute(
	EVMHost& _hostContext,
	std::string _sourceCode,
	std::string _contractName,
	std::string _methodName,
	frontend::OptimiserSettings _optimisation,
	std::string _libraryName
)
{
	bytes libraryBytecode;
	Json::Value libIds;
	std::map<std::string, solidity::util::h160> _libraryAddressMap;

	// First deploy library
	if (!_libraryName.empty())
	{
		tie(libraryBytecode, libIds) = compileContract(
			_sourceCode,
			_libraryName,
			{},
			_optimisation
		);
		// Deploy contract and signal failure if deploy failed
		evmc::result createResult = deployContract(_hostContext, libraryBytecode);
		solAssert(
			createResult.status_code == EVMC_SUCCESS,
			"Proto solc fuzzer: Library deployment failed"
		);
		_libraryAddressMap[_libraryName] = EVMHost::convertFromEVMC(createResult.create_address);
	}

	auto [bytecode, ids] = compileContract(
		_sourceCode,
		_contractName,
		_libraryAddressMap,
		_optimisation
	);

	return deployAndExecute(
		_hostContext,
		bytecode,
		ids[_methodName].asString()
	);
}

std::pair<solidity::bytes, Json::Value> EVMOneUtility::compileContract(
	std::string _sourceCode,
	std::string _contractName,
	std::map<std::string, solidity::util::h160> const& _libraryAddresses,
	frontend::OptimiserSettings _optimisation
)
{
	try
	{
		// Compile contract generated by the proto fuzzer
		SolidityCompilationFramework solCompilationFramework;
		return std::make_pair(
			solCompilationFramework.compileContract(_sourceCode, _contractName, _libraryAddresses, _optimisation),
			solCompilationFramework.getMethodIdentifiers()
		);
	}
	// Ignore stack too deep errors during compilation
	catch (evmasm::StackTooDeepException const&)
	{
		return std::make_pair(bytes{}, Json::Value(0));
	}
}
