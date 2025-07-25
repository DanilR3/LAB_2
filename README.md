Завдання 1: Аналізатор лог-файлів
Напишіть функцію analyze_log_file(log_file_path), яка приймає шлях до файлу журналу http-сервера (текстового файлу). Функція повинна:
Прочитати кожний рядок файлу. Типовий лог-файл “apache_logs.txt” додається
Визначити кількість входжень унікальний кодів відповідей http-сервера (наприклад, 200, 404, 500 і т.д.).
Зберегти результати у словнику, де ключем є код відповіді, а значенням - кількість його входжень.
Обробити можливі винятки, такі як відсутність файлу (FileNotFoundError) або помилки читання файлу (IOError), виводячи інформативне повідомлення про помилку.
Повернути отриманий словник з результатами аналізу.

Завдання 2: Генератор хешів файлів
Створіть функцію generate_file_hashes(*file_paths), яка приймає список шляхів до файлів. Для кожного файлу у списку функція повинна:
Відкрити файл у бінарному режимі для читання.
Обчислити хеш SHA-256 вмісту файлу.
Зберегти результати у словнику, де ключем є шлях до файлу, а значенням - його SHA-256 хеш (у шістнадцятковому форматі).
Обробити можливі винятки, такі як відсутність файлу (FileNotFoundError) або помилки читання файлу (IOError), виводячи відповідне повідомлення.
Повернути словник з хешами файлів.
Для обчислення хешів скористайтеся бібліотекою hashlib.

Завдання 3: Фільтрація IP-адрес з файлу
Напишіть функцію filter_ips(input_file_path, output_file_path, allowed_ips), яка аналізує IP-адреси з лог-файла http-сервера:
Читає IP-адреси з кожного рядка файлу input_file_path. 
Перевіряє, чи кожна прочитана IP-адреса присутня у списку дозволених IP-адрес allowed_ips. Попередньо необхідно задати список (масив) дозволених IP-адрес allowed_ips.
Рахує скільки разів зустрічаються дозволені адреси у лог файлі.
Записує результат аналізу лог-файлу до файлу output_file_path, у вигляді <IP адерса> - <кількість входженнь>.
Обробити можливі винятки, такі як відсутність вхідного файлу (FileNotFoundError) або помилки запису до вихідного файлу (IOError), виводячи інформативні повідомлення.
