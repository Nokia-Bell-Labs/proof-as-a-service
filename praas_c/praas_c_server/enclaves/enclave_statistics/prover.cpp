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

    int num_elements = 0;
    double num_elements_double;
    uint8_t rval;
    bool* selected_indices;
    int *input_integers;

    int sum = 0, min = 0, max = 0;
    int p10, p25, p50, p75, p90, p95, p99; 
    double stdev;
    double mean;

    char* line;
    int pos = 0;

    for (int i = 0; i < size_input_data; i++)
    {
        if (*(input_data+i) == 10)
        {
            num_elements++;
        }
    }

    printf("size_input_data: %ld, num elements: %d\n", size_input_data, num_elements);

    input_integers = (int *) malloc (num_elements * sizeof(int));

    for (int i = 0, j = 0; i < size_input_data; i++)
    {
        if (*(input_data+i) == 10)
        {
            line = (char*) malloc(sizeof(char) * (i-pos+1));
            memcpy(line, input_data+pos, i - pos);
            line[i-pos] = '\0';
            int k = atoi(line);
            //printf("i: %d, pos: %d, line: %s, k: %d\n", i, pos, line, k);
            memcpy(input_integers+j, &k, sizeof(int));
            pos = i+1;
            j++;
            free(line);
        }
    }

    // sort the dataset
    // compute mean, min, max, percentiles
    //printf("input data: ");
    for (int i = 0; i < num_elements; i++)
    {
        //printf("%d: %d \n", i, input_integers[i]);
        sum+= input_integers[i];
    }
    sort(input_integers, input_integers + num_elements);
    num_elements_double = (double) num_elements;
    min = input_integers[0];
    p10 = input_integers[(int)(num_elements_double / 100 * 10) - 1];
    p25 = input_integers[(int)(num_elements_double / 100 * 25) - 1];
    p50 = input_integers[(int)(num_elements_double / 100 * 50) - 1];
    p75 = input_integers[(int)(num_elements_double / 100 * 75) - 1];
    p90 = input_integers[(int)(num_elements_double / 100 * 90) - 1];
    p95 = input_integers[(int)(num_elements_double / 100 * 95) - 1];
    p99 = input_integers[(int)(num_elements_double / 100 * 99) - 1];
    max = input_integers[(int)(num_elements_double)-1];
    /*printf("sorted: ");
    for (int i = 0; i < num_elements; i++)
    {
        printf("%d: %d \n", i, input_integers[i]);
    }
    */
    mean = sum / num_elements;

    printf("min: %d, max: %d, mean: %lf, sum: %d\n", min, max, mean, sum);
    printf("percentiles: %d, %d, %d, %d, %d, %d, %d\n", p10, p25, p50, p75, p90, p95, p99);

    *size_output_data = sizeof(int)*10 + sizeof(double) + 11;
    *output_data = (uint8_t*) malloc(sizeof(uint8_t) * *size_output_data);
    memcpy(*output_data, &min, 4);
    memcpy(*output_data+4, " ", 1);
    memcpy(*output_data+5, &max, 4);
    memcpy(*output_data+9, " ", 1);
    memcpy(*output_data+10, &mean, 8);
    memcpy(*output_data+18, " ", 1);
    memcpy(*output_data+19, &sum, 4);
    memcpy(*output_data+23, " ", 1);
    memcpy(*output_data+24, &p10, 4);
    memcpy(*output_data+28, " ", 1);
    memcpy(*output_data+29, &p25, 4);
    memcpy(*output_data+33, " ", 1);
    memcpy(*output_data+34, &p50, 4);
    memcpy(*output_data+38, " ", 1);
    memcpy(*output_data+39, &p75, 4);
    memcpy(*output_data+43, " ", 1);
    memcpy(*output_data+44, &p90, 4);
    memcpy(*output_data+48, " ", 1);
    memcpy(*output_data+49, &p95, 4);
    memcpy(*output_data+53, " ", 1);
    memcpy(*output_data+54, &p99, 4);
    *(*output_data+58) = '\0';

    ret = 0;

exit:
    if (input_integers)
    {
        free(input_integers);
    }
    return ret;
}
