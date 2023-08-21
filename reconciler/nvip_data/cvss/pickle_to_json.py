import pickle
import os
import csv
from statistics import median

data_path = './'
pickle_file = 'CVE-CWE-CVSS-Vectors-v3-tCVE.pickle'
states_csv = 'vector_outputs.csv'
cvss_file = 'cvss_map.csv'


def match(our_vector, nvd_vector):
    for i in range(8):
        vi = our_vector[i]
        wi = nvd_vector[i]
        # vectors match if they're the same or if all mismatches are one of the following cases:
        # there's an 'X' in that position in the first of the vectors, or
        # there's an 'LH' in the first and there's an 'L' or 'H' in the other
        # this is not symmetric and is not an equivalence relation!
        if vi != wi \
                and vi != 'X'\
                and not (vi == 'LH' and (wi == 'L' or wi == 'H')):
            return False
    return True


def get_nvd_data():
    with open(os.path.join(data_path, pickle_file), 'rb') as f:
        return pickle.load(f)


def get_possible_inputs():
    out = []
    with open(os.path.join(data_path, states_csv), 'r') as f:
        csv_reader = csv.reader(f)
        for line in csv_reader:
            out.append(line)
    return out


def write_lookup(mapping):
    with open(os.path.join(data_path, cvss_file), 'w', newline='') as f:
        csv_writer = csv.writer(f)
        csv_writer.writerows(mapping)


def main():
    nvd_data = get_nvd_data()
    input_to_median = []
    for input in get_possible_inputs():
        scores = []
        for nvd_vec in nvd_data:
            if match(input, nvd_vec[8:]):
                scores.append(nvd_vec[5])
        input_to_median.append([','.join(input), median(scores) if len(scores) > 0 else -1])
    write_lookup(input_to_median)


if __name__ == '__main__':
    main()
