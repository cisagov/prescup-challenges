#!/usr/bin/env python3

import numpy as np
import pandas as pd
import sys
import os
import math
from collections import Counter

def hex_to_int(hex_str : str) -> int :
  return int(hex_str, 16)

def compute_entropy(domain):
  freq = Counter(domain)
  total = len(domain)
  return -sum((count/total) * math.log2(count/total) for count in freq.values())

def extract_features(domain):
  subdomain = domain.split('.')[0]
  domain_main = domain.split('.')[1]

  num_letters = sum(c.isalpha() for c in domain)
  num_vowels = sum(c in "aeiou" for c in domain)
  num_consonants = num_letters - num_vowels
  num_unique_chars = len(set(domain_main))
  subdomain_val = hex_to_int(subdomain)
  entropy = compute_entropy(domain)

  return {
    # "num_letters": num_letters,
    # "num_vowels": num_vowels,
    # "num_consonants": num_consonants,
    "num_unique_chars": num_unique_chars,
    "subdomain_val": subdomain_val,
    "entropy": entropy,
  }

def train(training_data, test_data):
  # Convert to DataFrame
  training_df = pd.DataFrame(training_data, columns=["domain"])
  full_df = pd.DataFrame(training_data + test_data, columns=["domain"])

  # Convert dataset to numerical feature vectors
  training_matrix = pd.DataFrame([extract_features(d) for d in training_df["domain"]])
  full_matrix = pd.DataFrame([extract_features(d) for d in full_df["domain"]])

  full_matrix_mean_vector = full_matrix.mean()
  full_matrix_variance_vector = full_matrix.var()

  # Normalize features
  training_matrix_normalized = (training_matrix - full_matrix_mean_vector) / (full_matrix.std() + 1e-5)
  full_matrix_normalized = (full_matrix - full_matrix_mean_vector) / (full_matrix.std() + 1e-5)

  full_matrix_normalized_mean_vector = full_matrix_normalized.mean()
  full_matrix_normalized_variance_vector = full_matrix_normalized.var()

  # Compute distances for known class
  known_distances = np.sqrt(((training_matrix_normalized - full_matrix_normalized_mean_vector) ** 2 / (full_matrix_normalized_variance_vector + 1e-5)).sum(axis=1))

  # Set threshold dynamically using the mean and standard deviation of known distances
  threshold = known_distances.mean() + 8 * known_distances.std()

  print(full_matrix_normalized)

  return full_matrix_mean_vector, full_matrix_variance_vector, full_matrix_normalized_mean_vector, full_matrix_normalized_variance_vector, threshold

def classify(domain, mean_vector, variance_vector, normalized_mean_vector, normalized_variance_vector, threshold=0.5):
  features = extract_features(domain)
  feature_vector = np.array([(features[key] - mean_vector[key]) / (np.sqrt(variance_vector[key]) + 1e-3) for key in mean_vector.index])

  # Compute Mahalanobis-like distance
  distance = np.sum((feature_vector - normalized_mean_vector) ** 2 / (normalized_variance_vector + 1e-5)) 
  
  # print(feature_vector, distance, threshold)

  return 1 if distance < threshold else 0  # 1 = Known class, 0 = Anomaly

def run(training_data, test_data, classified_data_file_path):
  mean_vector, variance_vector, normalized_mean_vector, normalized_variance_vector, threshold = train(training_data, test_data)

  # correct = 0
  with open(classified_data_file_path, 'w') as classified_file:
    for domain in test_data:
      result = classify(domain, mean_vector, variance_vector, normalized_mean_vector, normalized_variance_vector, threshold)
      classified_file.write(f"{domain},{result}\n")
    # if result == label:
    #   correct += 1

  # print(f"Accuracy: {correct / len(test_data) * 100:.2f}%")

  return

if __name__ == "__main__":
  if len(sys.argv) != 4:
    print("Usage: classify_data.py <training_data_path> <test_data_path> <output_path>")
    sys.exit(1)
  
  training_data_file_path = sys.argv[1]
  test_data_file_path = sys.argv[2]
  classified_data_file_path = sys.argv[3]

  if not os.path.isfile(training_data_file_path) or not os.access(training_data_file_path, os.R_OK):
    print(f"Error: Cannot read training data file at {training_data_file_path}")
    sys.exit(1)

  if not os.path.isfile(test_data_file_path) or not os.access(test_data_file_path, os.R_OK):
    print(f"Error: Cannot read test data file at {test_data_file_path}")
    sys.exit(1)

  with open(training_data_file_path, 'r') as training_file:
    training_data = training_file.readlines()
    training_data = [line.strip() for line in training_data if line.strip()]

  with open(test_data_file_path, 'r') as test_file:
    test_data = test_file.readlines()
    test_data = [line.strip() for line in test_data if line.strip()]

  run(training_data, test_data, classified_data_file_path)