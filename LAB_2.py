def analyze_log_file(log_file_path):
    response_counts = {}  

    try:
        with open(log_file_path, "r") as file:
            for line in file:
                parts = line.strip().split()  
                if len(parts) > 8:
                    code = parts[8]  
                    if code.isdigit():  
                        if code in response_counts:
                            response_counts[code] += 1
                        else:
                            response_counts[code] = 1

    except FileNotFoundError:
        print("Файл не знайдено:", log_file_path)
    except IOError:
        print("Помилка при читанні файлу:", log_file_path)

    return response_counts


print(analyze_log_file("apache_logs.txt"))


import hashlib

def generate_file_hashes(*file_paths):
    hashes = {}  

    for path in file_paths:
        try:
            with open(path, "rb") as file:  
                file_data = file.read()
                file_hash = hashlib.sha256(file_data).hexdigest()
                hashes[path] = file_hash

        except FileNotFoundError:
            print("Файл не знайдено:", path)
        except IOError:
            print("Помилка при читанні файлу:", path)

    return hashes


print(generate_file_hashes("file1.txt", "file2.txt"))


def filter_ips(input_file_path, output_file_path, allowed_ips):
    ip_counts = {}  

    try:
        with open(input_file_path, "r") as infile:
            for line in infile:
                parts = line.strip().split()
                if len(parts) > 0:
                    ip = parts[0]  
                    if ip in allowed_ips:
                        if ip in ip_counts:
                            ip_counts[ip] += 1
                        else:
                            ip_counts[ip] = 1

        
        try:
            with open(output_file_path, "w") as outfile:
                for ip, count in ip_counts.items():
                    outfile.write(f"{ip} - {count}\n")

        except IOError:
            print("Помилка при записі у файл:", output_file_path)

    except FileNotFoundError:
        print("Вхідний файл не знайдено:", input_file_path)
    except IOError:
        print("Помилка при читанні вхідного файлу:", input_file_path)


allowed = ["192.123.1.0", "23.7.8.3"]
filter_ips("apache_logs.txt", "filtered_ips.txt", allowed)

