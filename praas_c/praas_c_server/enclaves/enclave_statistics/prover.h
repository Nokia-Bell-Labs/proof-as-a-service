/*
© 2024 Nokia
Licensed under the BSD 3-Clause Clear License
SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#pragma once
#include <openenclave/enclave.h>
#include <string>

using namespace std;

class Prover
{
  private:

  public:
    Prover();
    ~Prover();

    // must be exposed for the dispatcher as the entry point
    int do_computation(const uint8_t* input_data, const size_t size_input_data, uint8_t** output_data, size_t* size_output_data);

  private:

};
