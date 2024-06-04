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

    const int size_element = sizeof(int);
    int num_elements = 0, num_sample;
    unsigned int rval;
    bool* selected_indices;
    int *input_integers;
    int *sample_integers;

    int sum = 0, min = 0, max = 0;
    int p10, p25, p50, p75, p90, p95, p99; 
    double stdev;
    double mean;

    for (int i = 0; i < size_input_data; i++)
    {
        if (*(input_data+i) == 10)
        {
            num_elements++;
        }
    }

    printf("size_input_data: %ld, num elements: %d\n", size_input_data, num_elements);

    num_sample = num_elements / 100.0 * 5.0;
    double num_sample_double = (double) num_sample;

    printf("num_sample: num: %d\n", num_sample);

    input_integers = (int *) malloc (num_elements * size_element);
    sample_integers = (int *) malloc (num_sample * size_element);

    char* line;
    int pos = 0;
    for (int i = 0, j = 0; i < size_input_data; i++)
    {
        if (*(input_data+i) == 10)
        {
            line = (char*) malloc(sizeof(char) * (i-pos+1));
            memcpy(line, input_data+pos, i - pos);
            line[i-pos] = '\0';
            int k = atoi(line);
            //printf("i: %d, pos: %d, line: %s, k: %d\n", i, pos, line, k);
            memcpy(input_integers+j, &k, size_element);
            pos = i+1;
            j++;
            free(line);
        }
    }

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
        //printf("i: %d, index: %u, sampled_item: %d\n", i, index, input_integers[index]);
        sample_integers[i] = input_integers[index];
    }

    free(selected_indices);

    // sort the dataset
    // compute mean, min, max, percentiles
    //printf("input data: ");
    for (int i = 0; i < num_sample; i++)
    {
        //printf("%d: %d \n", i, sample_integers[i]);
        sum+= sample_integers[i];
    }
    sort(sample_integers, sample_integers + num_sample);
    //min = input_integers[0];
    p10 = sample_integers[(int)(num_sample_double / 100 * 10) - 1];
    p25 = sample_integers[(int)(num_sample_double / 100 * 25) - 1];
    p50 = sample_integers[(int)(num_sample_double / 100 * 50) - 1];
    p75 = sample_integers[(int)(num_sample_double / 100 * 75) - 1];
    p90 = sample_integers[(int)(num_sample_double / 100 * 90) - 1];
    p95 = sample_integers[(int)(num_sample_double / 100 * 95) - 1];
    p99 = sample_integers[(int)(num_sample_double / 100 * 99) - 1];
    //max = input_integers[num_elements-1];
    //printf("sorted: ");
    //for (int i = 0; i < num_sample; i++)
    //{
    //    printf("%d: %d \n", i, sample_integers[i]);
    //}
    
    mean = sum / num_sample;

    printf("mean: %lf\n", mean);
    printf("percentiles: %d, %d, %d, %d, %d, %d, %d\n", p10, p25, p50, p75, p90, p95, p99);

    *size_output_data = sizeof(int)*7 + sizeof(double) + 8;
    *output_data = (uint8_t*) malloc(sizeof(uint8_t) * *size_output_data);
    memcpy(*output_data, &mean, 8);
    memcpy(*output_data+8, " ", 1);
    memcpy(*output_data+9, &p10, 4);
    memcpy(*output_data+13, " ", 1);
    memcpy(*output_data+14, &p25, 4);
    memcpy(*output_data+18, " ", 1);
    memcpy(*output_data+19, &p50, 4);
    memcpy(*output_data+23, " ", 1);
    memcpy(*output_data+24, &p75, 4);
    memcpy(*output_data+28, " ", 1);
    memcpy(*output_data+29, &p90, 4);
    memcpy(*output_data+33, " ", 1);
    memcpy(*output_data+34, &p95, 4);
    memcpy(*output_data+38, " ", 1);
    memcpy(*output_data+39, &p99, 4);
    *(*output_data+43) = '\0';

    ret = 0;

exit:
    if (input_integers)
    {
        free(input_integers);
    }
    if (sample_integers)
    {
        free(sample_integers);
    }
    return ret;
}
