# © 2024 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

import os
import pickle
import sys
import tarfile

import torch
from torch.utils.data import random_split
from torchvision import datasets, transforms

DATASET_NAME = None
NUM_DATASETS = None

def init_data_cifar10():
    data_root= '/tmp/cifar10_data/'

    transform = transforms.Compose(
        [transforms.ToTensor(),
         transforms.Normalize((0.5, 0.5, 0.5), (0.5, 0.5, 0.5))]
    )
    train_data = datasets.CIFAR10(
            data_root,
            train=True,
            download=True,
            transform=transform,
            )

    test_data = datasets.CIFAR10(
            data_root,
            train=False,
            download=True,
            transform=transform
            )

    return train_data, test_data

def init_data_mnist():
    data_root= '/tmp/mnist_data/'

    train_data = datasets.MNIST(
            data_root,
            train=True,
            download=True,
            transform=transforms.Compose([
                transforms.ToTensor(),
                transforms.Normalize((0.1307,), (0.3081,)),
                ])
            )

    test_data = datasets.MNIST(
            data_root,
            train=False,
            download=True,
            transform=transforms.Compose([
                transforms.ToTensor(),
                transforms.Normalize((0.1307,), (0.3081,)),
                ])
            )

    return train_data, test_data

def init_data_fashionmnist():
    data_root= '/tmp/fashionmnist_data/'

    train_data = datasets.FashionMNIST(
            data_root,
            train=True,
            download=True,
            transform=transforms.ToTensor()
            )

    test_data = datasets.FashionMNIST(
            data_root,
            train=False,
            download=True,
            transform=transforms.ToTensor()
            )

    return train_data, test_data

if __name__ == '__main__':
    DATASET_NAME = sys.argv[1]
    NUM_DATASETS = int(sys.argv[2])

    torch.manual_seed(42)

    if DATASET_NAME == "cifar10":
        train_data, test_data = init_data_cifar10()
    elif DATASET_NAME == "mnist":
        train_data, test_data = init_data_mnist()
    elif DATASET_NAME == "fashionmnist":
        train_data, test_data = init_data_fashionmnist()
    else:
        print("Invalid dataset name")
        sys.exit(1)

    ASSETS_DIR = DATASET_NAME + "/"
    if not os.path.exists(ASSETS_DIR):
        os.mkdir(ASSETS_DIR)

    share_length = int(len(train_data) / NUM_DATASETS)
    random_datasets = random_split(train_data, [share_length for _ in range(NUM_DATASETS)])

    indices = [i for i in range(share_length)]
    for i, dataset in enumerate(random_datasets):
        print("Creating dataset: {}...".format(i))
        small_dataset = [dataset.dataset[i] for i in dataset.indices]
        dataset.dataset = small_dataset
        dataset.indices = indices

        data_filename = ASSETS_DIR + f'data_{i}'
        with open(data_filename, 'wb') as _f:
            pickle.dump(dataset, _f)

        # archive the file
        with tarfile.open(data_filename + ".tar.gz", "w:gz") as tar:
            tar.add(data_filename, f'data_{i}')

    print("Creating test dataset...")
    test_filename = ASSETS_DIR + 'data_test'
    with open(test_filename, 'wb') as _f:
        pickle.dump(test_data, _f)

    # archive the file
    with tarfile.open(test_filename + ".tar.gz", "w:gz") as tar:
        tar.add(test_filename, 'data_test')
