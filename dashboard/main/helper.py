
import csv

def get_log(file_path):
    content = []
    with open(file_path, mode='r', newline='') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            content.append(row)
    return content[1:]

def get_mac(file_path):
    content = []
    with open(file_path, mode='r', newline='') as file:
        content = file.readlines()
    return content


if __name__ == "__main__":
    table_data = get_log(r"./logs/preventions.csv")
    print(table_data)
