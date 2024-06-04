/*
© 2024 Nokia
Licensed under the BSD 3-Clause Clear License
SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include "prover.h"
#include <openenclave/enclave.h>

Prover::Prover()
{
}

Prover::~Prover()
{
}

int Prover::do_computation(const uint8_t* input_data, const size_t size_input_data, uint8_t** output_data, size_t* size_output_data)
{
    int ret = 1;

    // each actual element is 64 bytes (sha256 in hex)
    // 64 + 1 for each new line
    const int size_element = 65;
    int num_elements, num_sample;
    unsigned int rval;
    bool* selected_indices;

    num_elements = size_input_data / size_element;
    printf("num elements: %d\n", num_elements);

    num_sample = num_elements / 100.0 * 5.0;
    printf("num_sample: num: %u\n", num_sample);

    *size_output_data = num_sample * size_element;
    *output_data = (uint8_t*) malloc (sizeof(uint8_t) * *size_output_data);
    selected_indices = (bool*) malloc (num_elements);
    for (int i = 0; i < num_elements; i++)
    {
        selected_indices[i] = false;
    }
    for (int i = 0; i < num_sample; i++)
    {
        oe_random(&rval, sizeof(int));
        int index = rval % num_elements;
        //printf("i: %d, rval: %u, index: %u\n", i, rval, index);
        while (selected_indices[index])
        {
            oe_random(&rval, sizeof(int));
            index = rval % num_elements;
            //printf("retrying i: %d, rval: %u, index: %u\n", i, rval, index);
        }
        selected_indices[index] = true;
        //printf("i: %d, index: %u\n", i, index);
        memcpy(*output_data + i*size_element, input_data + index*size_element, size_element);
    }

    printf("output_data: num: %d size: %zu\n", num_sample, *size_output_data);

    /*
    for (uint32_t i = 0; i < num_sample; i++)
    {
        for (uint8_t j = 0; j < size_element; j++)
        {
            printf("%c", (*output_data)[i*size_element+j]);
        }
        //printf("\n");
    }
    printf("\n");
    */
    free(selected_indices);

    ret = 0;

exit:
    return ret;
}
