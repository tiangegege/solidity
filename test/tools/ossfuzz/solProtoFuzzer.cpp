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

#include <test/tools/ossfuzz/protoToSol.h>
#include <test/tools/ossfuzz/SolidityEvmOneInterface.h>
#include <test/tools/ossfuzz/solProto.pb.h>

#include <test/EVMHost.h>

#include <evmone/evmone.h>
#include <src/libfuzzer/libfuzzer_macro.h>

#include <fstream>

static evmc::VM evmone = evmc::VM{evmc_create_evmone()};

using namespace solidity::test::fuzzer;
using namespace solidity::test::solprotofuzzer;
using namespace solidity;
using namespace solidity::test;
using namespace solidity::util;
using namespace std;

namespace
{
/// Expected output value is decimal 0
static vector<uint8_t> const expectedOutput(32, 0);
}

DEFINE_PROTO_FUZZER(Program const& _input)
{
	ProtoConverter converter;
	string sol_source = converter.protoToSolidity(_input);

	if (char const* dump_path = getenv("PROTO_FUZZER_DUMP_PATH"))
	{
		// With libFuzzer binary run this to generate a YUL source file x.yul:
		// PROTO_FUZZER_DUMP_PATH=x.yul ./a.out proto-input
		ofstream of(dump_path);
		of.write(sol_source.data(), static_cast<streamsize>(sol_source.size()));
	}

	if (char const* dump_path = getenv("SOL_DEBUG_FILE"))
	{
		sol_source.clear();
		// With libFuzzer binary run this to generate a YUL source file x.yul:
		// PROTO_FUZZER_LOAD_PATH=x.yul ./a.out proto-input
		ifstream ifstr(dump_path);
		sol_source = {
			std::istreambuf_iterator<char>(ifstr),
			std::istreambuf_iterator<char>()
		};
		std::cout << sol_source << std::endl;
	}

	// We target the default EVM which is the latest
	langutil::EVMVersion version = {};
	EVMHost hostContext(version, evmone);

	auto minimalResult = EVMOneUtility::compileDeployAndExecute(
		hostContext,
		sol_source,
		":C",
		"test()",
		frontend::OptimiserSettings::minimal(),
		converter.libraryTest() ? converter.libraryName() : ""
	);
	bool successState = minimalResult.status_code == EVMC_SUCCESS;
	if (successState)
		solAssert(
			EVMOneUtility::isOutputExpected(minimalResult.output_data, minimalResult.output_size, expectedOutput),
			"Proto solc fuzzer: Output incorrect"
		);
}
