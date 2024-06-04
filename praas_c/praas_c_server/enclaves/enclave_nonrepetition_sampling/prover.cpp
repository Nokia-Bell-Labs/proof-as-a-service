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

int Prover::cmpstr(const void* a, const void* b)
{
    const char* aa = *(const char**)a;
    const char* bb = *(const char**)b;
    return strcmp(aa, bb);
}

bool Prover::check_duplicates(char** input_array, size_t num_elements, int size)
{
    bool ret = true;
    for (size_t i = 0; i < num_elements-1; i++)
    {
        int res = strncmp(input_array[i], input_array[i+1], size);
        //printf("%.*s, %.*s %d\n", size, input_array[i], size, input_array[i+1], res);
        if (res == 0)
        {
            ret = false;
            break;
        }
    }
    return ret;
}

int Prover::do_computation(const uint8_t* input_data, const size_t size_input_data, uint8_t** output_data, size_t* size_output_data)
{
    int ret = 1;

    // each actual element is 64 bytes (sha256 in hex)
    // 64 + 1 for each new line
    const int size_element = 65;
    size_t num_elements, num_sample;
    unsigned int rval;
    bool* selected_indices;
    char** input_array;

    num_elements = size_input_data / size_element;
    printf("num elements: %ld\n", num_elements);

    input_array = (char**) malloc (num_elements * sizeof(char*));
    if (input_array == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        printf("out of memory (input_array)");
        goto exit;
    }
    for (int i = 0; i < num_elements; i++)
    {
        input_array[i] = (char*) malloc (size_element);
        if (input_array[i] == nullptr)
        {
            ret = OE_OUT_OF_MEMORY;
            printf("out of memory (input_array[i])");
            goto exit;
        }
    }

    selected_indices = (bool*) malloc (num_elements);
    if (selected_indices == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        printf("out of memory (selected_indices)");
        goto exit;
    }

    for (int i = 0; i < num_elements; i++)
    {
        selected_indices[i] = false;
        memcpy(input_array[i], input_data + i*size_element, size_element);
        //printf("element i: %d => %.*s\n", i, 64, input_array[i]);
    }

    qsort((void *) input_array, num_elements, sizeof(char*), cmpstr);

    /*
    for (int i = 0; i < num_elements; i++)
    {
        printf("element i: %d => %.*s\n", i, 64, input_array[i]);
    }
    */
    if (!check_duplicates(input_array, num_elements, size_element-1))
    {
        for (int i = 0; i < num_elements; i++)
        {
            free(input_array[i]);
        }
        free(input_array);
        goto exit;
    }

    for (int i = 0; i < num_elements; i++)
    {
        free(input_array[i]);
    }
    free(input_array);

    num_sample = num_elements / 100.0 * 5.0;
    printf("num_sample: num: %lu\n", num_sample);

    *size_output_data = num_sample * size_element;
    *output_data = (uint8_t*) malloc (sizeof(uint8_t) * *size_output_data);

    if (*output_data == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        printf("out of memory (output_data)");
        goto exit;
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

    printf("output_data: num: %ld size: %zu\n", num_sample, *size_output_data);

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
