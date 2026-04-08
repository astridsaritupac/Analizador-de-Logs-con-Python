import re
from collections import Counter

# Expresión regular para parsear Apache Logs
LOG_PATTERN = r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<date>.*?)\] "(?P<method>\w+) (?P<url>.*?) HTTP/.*?" (?P<status>\d{3})'

def analyze_logs(file_path):
    ip_counts = Counter()
    failed_requests = []
    
    with open(file_path, 'r') as file:
        for line in file:
            match = re.search(LOG_PATTERN, line)
            if match:
                data = match.groupdict()
                ip = data['ip']
                status = data['status']
                
                # Contar hits por IP
                ip_counts[ip] += 1
                
                # Detectar posibles ataques (Status 404 o 403)
                if status in ['404', '403']:
                    failed_requests.append(data)

    return ip_counts, failed_requests

# Ejemplo de ejecución
if __name__ == "__main__":
    ips, failures = analyze_logs('access.log')
    print(f"Top Atacantes/Usuarios: {ips.most_common(5)}")
    print(f"Total de peticiones fallidas: {len(failures)}")