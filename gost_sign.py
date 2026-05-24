#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import sys
import time
import math
import ctypes
import os
from typing import Optional, Tuple

BASE_DIR = r"C:\Users\kholostykh.iuv\Desktop\gost"
os.makedirs(BASE_DIR, exist_ok=True)

if sys.platform == 'win32':
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except:
        pass

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    MAGENTA = '\033[35m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_logo():
    print(Colors.BOLD + Colors.CYAN + """
    ************************************************************
    *              ГОСТ Р 34.10-2012                           *
    *   ЭЛЕКТРОННАЯ ЦИФРОВАЯ ПОДПИСЬ НА ЭЛЛИПТИЧЕСКИХ КРИВЫХ    *
    ************************************************************
    """ + Colors.END)
    print(Colors.CYAN + "   Автор: Information Security Specialist, Y. V. Kholostykh" + Colors.END)
    print(Colors.CYAN + "   GitHub: https://github.com/yvkholostykh?tab=repositories" + Colors.END)
    print()

def print_header(title):
    print(Colors.BOLD + Colors.BLUE + "=" * 70 + Colors.END)
    print(Colors.BOLD + Colors.YELLOW + title.center(70) + Colors.END)
    print(Colors.BOLD + Colors.BLUE + "=" * 70 + Colors.END)

def print_step(step_name):
    print(f"\n{Colors.MAGENTA}--- {step_name} ---{Colors.END}")

def print_success(msg): print(Colors.GREEN + "[OK] " + msg + Colors.END)
def print_error(msg):   print(Colors.RED + "[ERR] " + msg + Colors.END)
def print_info(msg):    print(Colors.CYAN + "[i] " + msg + Colors.END)
def print_warning(msg): print(Colors.YELLOW + "[!] " + msg + Colors.END)

# ---------------------- ЭЛЛИПТИЧЕСКАЯ КРИВАЯ ----------------------
class EllipticCurve:
    def __init__(self, p: int, a: int, b: int):
        self.p = p
        self.a = a
        self.b = b

    def is_on_curve(self, point: Optional[Tuple[int, int]]) -> bool:
        if point is None:
            return True
        x, y = point
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def add(self, P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and y1 == y2:
            if y1 == 0:
                return None
            num = (3 * x1 * x1 + self.a) % self.p
            den = (2 * y1) % self.p
            inv_den = pow(den, -1, self.p)
            lam = (num * inv_den) % self.p
        else:
            if x1 == x2:
                return None
            num = (y2 - y1) % self.p
            den = (x2 - x1) % self.p
            inv_den = pow(den, -1, self.p)
            lam = (num * inv_den) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def mul(self, P: Optional[Tuple[int, int]], n: int) -> Optional[Tuple[int, int]]:
        if n == 0 or P is None:
            return None
        result = None
        current = P
        while n:
            if n & 1:
                result = self.add(result, current)
            current = self.add(current, current)
            n >>= 1
        return result

    def order(self, G: Tuple[int, int], max_order: int) -> int:
        Q = G
        for i in range(2, max_order + 1):
            Q = self.add(Q, G)
            if Q is None:
                return i
        raise ValueError(f"Порядок точки не найден (макс. {max_order})")

    def find_base_point(self, q: int) -> Tuple[int, int]:
        print(Colors.CYAN + "[Поиск базовой точки G порядка q на кривой...]" + Colors.END)
        for x in range(self.p):
            rhs = (x * x * x + self.a * x + self.b) % self.p
            y = pow(rhs, (self.p + 1) // 4, self.p)
            if (y * y) % self.p == rhs:
                try:
                    if self.order((x, y), q + 1) == q:
                        return (x, y)
                except:
                    continue
        raise RuntimeError("Не удалось найти точку порядка q")

# ---------------------- ГОСТ Р 34.10-2012 ----------------------
class GOST3410_2012:
    def __init__(self, p: int, a: int, b: int, q: int):
        self.curve = EllipticCurve(p, a, b)
        self.q = q
        self.G = self.curve.find_base_point(q)
        print(Colors.GREEN + f"[OK] Базовая точка G = {self.G}" + Colors.END)
        time.sleep(1)

    def simple_hash(self, message: str) -> int:
        l = math.floor(math.log2(self.q))
        msg_bytes = message.encode('utf-8')
        bits = ''.join(format(byte, '08b') for byte in msg_bytes)
        total = 0
        for i in range(0, len(bits), l):
            block_bits = bits[i:i+l]
            if len(block_bits) < l:
                block_bits = block_bits.ljust(l, '0')
            total = (total + int(block_bits, 2)) % (1 << l)
        e = total % self.q
        return e if e != 0 else 1

    def generate_keypair(self, verbose: bool = True) -> Tuple[int, Tuple[int, int]]:
        if verbose:
            print_header("ГЕНЕРАЦИЯ КЛЮЧЕВОЙ ПАРЫ")
        d = random.randint(1, self.q - 1)
        if verbose:
            print(f"   [Секретный ключ] d = {d}")
            print(f"   [Вычисление открытого ключа] Q = [d]G ...")
        Q = self.curve.mul(self.G, d)
        if verbose:
            print(f"   [Открытый ключ] Q = {Q}")
            print(Colors.GREEN + "=" * 70 + Colors.END + "\n")
        return d, Q

    def sign(self, message: str, private_key: int, verbose: bool = True) -> Tuple[int, int]:
        if verbose:
            print_header("ФОРМИРОВАНИЕ ПОДПИСИ")
            print(f"   [Сообщение] M = '{message}'")
        e = self.simple_hash(message)
        if verbose:
            print_step("Шаг 1. Хэш-код e = H(M)")
            print(f"      e = {e}")
        for attempt in range(1, 101):
            k = random.randint(1, self.q - 1)
            if verbose:
                print_step(f"Попытка {attempt}: выбор случайного k")
                print(f"      k = {k}")
            C = self.curve.mul(self.G, k)
            if C is None:
                continue
            r = C[0] % self.q
            if verbose:
                print(f"      r = x_C mod q = {r}")
            if r == 0:
                continue
            s = (private_key * r + k * e) % self.q
            if verbose:
                print(f"      s = (d·r + k·e) mod q = ({private_key}·{r} + {k}·{e}) mod {self.q} = {s}")
            if s != 0:
                if verbose:
                    print(f"\n{Colors.GREEN}[OK] Подпись (r, s) = ({r}, {s}) успешно создана.{Colors.END}")
                    print(Colors.GREEN + "=" * 70 + Colors.END + "\n")
                return r, s
        raise RuntimeError("Не удалось создать подпись")

    def verify(self, message: str, signature: Tuple[int, int], public_key: Tuple[int, int], verbose: bool = True) -> bool:
        r, s = signature
        if verbose:
            print_header("ПРОВЕРКА ПОДПИСИ")
            print(f"   [Сообщение] M = '{message}'")
            print(f"   [Подпись] (r, s) = ({r}, {s})")
            print(f"   [Открытый ключ] Q = {public_key}")

        if not (0 < r < self.q and 0 < s < self.q):
            if verbose:
                print(f"\n{Colors.RED}[Ошибка] 0 < r,s < q не выполнено{Colors.END}")
            return False

        e = self.simple_hash(message)
        if verbose:
            print_step("Шаг 2. Хэш-код e = H(M)")
            print(f"      e = {e}")

        if verbose:
            print_step("Шаг 3. Вычисление v = e⁻¹ mod q")
        try:
            v = pow(e, -1, self.q)
        except ValueError:
            if verbose:
                print(f"      {Colors.RED}Ошибка: e не обратимо{Colors.END}")
            return False
        if verbose:
            print(f"      v = {v}")

        z1 = (s * v) % self.q
        z2 = (-r * v) % self.q
        if verbose:
            print_step("Шаг 4. Вычисление z1 = s·v mod q, z2 = -r·v mod q")
            print(f"      z1 = {s}·{v} mod {self.q} = {z1}")
            print(f"      z2 = -{r}·{v} mod {self.q} = {z2}")

        if verbose:
            print_step("Шаг 5. Вычисление C = [z1]G + [z2]Q")
        P1 = self.curve.mul(self.G, z1)
        P2 = self.curve.mul(public_key, z2)
        if P1 is None or P2 is None:
            if verbose:
                print(f"      {Colors.RED}Ошибка: одна из точек не определена{Colors.END}")
            return False
        C = self.curve.add(P1, P2)
        if C is None:
            R = 0
        else:
            R = C[0] % self.q
        if verbose:
            print(f"      R = x_C mod q = {R}")

        if verbose:
            print_step("Шаг 6. Сравнение R и r")
            print(f"      R = {R}, r = {r}")

        if R == r:
            if verbose:
                print(f"\n{Colors.GREEN}[OK] ПОДПИСЬ ВЕРНА{Colors.END}")
                print(Colors.GREEN + "=" * 70 + Colors.END + "\n")
            return True
        else:
            if verbose:
                print(f"\n{Colors.RED}[ОШИБКА] ПОДПИСЬ НЕВЕРНА{Colors.END}")
                print(Colors.RED + "=" * 70 + Colors.END + "\n")
            return False

# ---------------------- РАБОТА С ФАЙЛАМИ ----------------------
def save_keys_to_files(private_key: int, public_key: Tuple[int, int], folder: str = BASE_DIR):
    try:
        with open(os.path.join(folder, "secret_key.txt"), "w", encoding="utf-8") as f:
            f.write(str(private_key))
        with open(os.path.join(folder, "public_key.txt"), "w", encoding="utf-8") as f:
            f.write(f"{public_key[0]}\n{public_key[1]}")
        print_success(f"Ключи сохранены в {folder}")
    except Exception as e:
        print_error(f"Ошибка сохранения ключей: {e}")

def save_message_to_file(message: str, folder: str = BASE_DIR):
    try:
        with open(os.path.join(folder, "message.txt"), "w", encoding="utf-8") as f:
            f.write(message)
        print_success(f"Сообщение сохранено в {os.path.join(folder, 'message.txt')}")
    except Exception as e:
        print_error(f"Ошибка сохранения сообщения: {e}")

def save_signature_to_file(r: int, s: int, folder: str = BASE_DIR):
    try:
        with open(os.path.join(folder, "signature.txt"), "w", encoding="utf-8") as f:
            f.write(f"{r}\n{s}")
        print_success(f"Подпись сохранена в {os.path.join(folder, 'signature.txt')}")
    except Exception as e:
        print_error(f"Ошибка сохранения подписи: {e}")

def load_message_from_file(filepath: str = None) -> Optional[str]:
    if filepath is None:
        filepath = os.path.join(BASE_DIR, "message.txt")
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            msg = f.read().strip()
        if not msg:
            print_error(f"Файл {filepath} пуст")
            return None
        print_success(f"Сообщение загружено из {filepath}")
        return msg
    except FileNotFoundError:
        print_error(f"Файл {filepath} не найден")
        return None
    except Exception as e:
        print_error(f"Ошибка чтения файла: {e}")
        return None

def load_signature_from_file(filepath: str = None) -> Optional[Tuple[int, int]]:
    if filepath is None:
        filepath = os.path.join(BASE_DIR, "signature.txt")
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) < 2:
            print_error(f"Файл {filepath} должен содержать две строки: r и s")
            return None
        r = int(lines[0].strip())
        s = int(lines[1].strip())
        print_success(f"Подпись загружена из {filepath}")
        return (r, s)
    except FileNotFoundError:
        print_error(f"Файл {filepath} не найден")
        return None
    except ValueError:
        print_error("Некорректный формат файла (ожидаются целые числа)")
        return None

def load_public_key_from_file(filepath: str = None) -> Optional[Tuple[int, int]]:
    if filepath is None:
        filepath = os.path.join(BASE_DIR, "public_key.txt")
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) < 2:
            print_error(f"Файл {filepath} должен содержать две строки: x и y")
            return None
        x = int(lines[0].strip())
        y = int(lines[1].strip())
        print_success(f"Открытый ключ загружен из {filepath}")
        return (x, y)
    except FileNotFoundError:
        print_error(f"Файл {filepath} не найден")
        return None
    except ValueError:
        print_error("Некорректный формат файла открытого ключа")
        return None

def interactive_load_verification_data(gost):
    print_info("Для проверки подписи необходимы три файла:")
    print("   1. Файл с сообщением (текст, UTF-8)")
    print("   2. Файл с подписью (две строки: r и s)")
    print("   3. Файл с открытым ключом (две строки: x и y)")
    print("Вы можете указать полные пути или имена файлов в рабочей папке.")
    print(f"   Рабочая папка по умолчанию: {BASE_DIR}")

    msg_path = input(Colors.CYAN + "   Путь к файлу сообщения (Enter для message.txt): " + Colors.END).strip()
    if not msg_path:
        msg_path = os.path.join(BASE_DIR, "message.txt")
    message = load_message_from_file(msg_path)
    if message is None:
        return None, None, None

    sig_path = input(Colors.CYAN + "   Путь к файлу подписи (Enter для signature.txt): " + Colors.END).strip()
    if not sig_path:
        sig_path = os.path.join(BASE_DIR, "signature.txt")
    signature = load_signature_from_file(sig_path)
    if signature is None:
        return None, None, None

    key_path = input(Colors.CYAN + "   Путь к файлу открытого ключа (Enter для public_key.txt): " + Colors.END).strip()
    if not key_path:
        key_path = os.path.join(BASE_DIR, "public_key.txt")
    public_key = load_public_key_from_file(key_path)
    if public_key is None:
        return None, None, None

    return message, signature, public_key

def file_operations_menu(gost, private_key, public_key, message, signature):
    while True:
        print(Colors.BOLD + Colors.YELLOW + "\n--- УПРАВЛЕНИЕ ФАЙЛАМИ ---" + Colors.END)
        print(f"   Рабочая папка: {Colors.CYAN}{BASE_DIR}{Colors.END}")
        print("   Ожидаемые имена файлов (в рабочей папке):")
        print("      secret_key.txt   – секретный ключ (одно число)")
        print("      public_key.txt   – открытый ключ (x и y по строкам)")
        print("      message.txt      – сообщение (UTF-8)")
        print("      signature.txt    – подпись (r и s по строкам)")
        print("\n   Доступные действия:")
        print(f"      {Colors.GREEN}a.{Colors.END} Сохранить ключи (в рабочую папку)")
        print(f"      {Colors.GREEN}b.{Colors.END} Сохранить сообщение (в рабочую папку)")
        print(f"      {Colors.GREEN}c.{Colors.END} Сохранить подпись (в рабочую папку)")
        print(f"      {Colors.GREEN}d.{Colors.END} Загрузить подпись и проверить (с указанием путей)")
        print(f"      {Colors.GREEN}e.{Colors.END} Загрузить открытый ключ (из рабочей папки)")
        print(f"      {Colors.GREEN}f.{Colors.END} Выбрать файл сообщения (произвольный путь)")
        print(f"      {Colors.GREEN}g.{Colors.END} Выбрать файл подписи (произвольный путь)")
        print(f"      {Colors.GREEN}0.{Colors.END} Назад")
        choice = input(Colors.BOLD + "   Выберите действие [a-g,0]: " + Colors.END).strip().lower()
        print()

        if choice == '0':
            break
        elif choice == 'a':
            if private_key is None:
                print_error("Нет ключей для сохранения. Сначала сгенерируйте их в главном меню (пункт 1).")
            else:
                save_keys_to_files(private_key, public_key, BASE_DIR)
        elif choice == 'b':
            if message is None:
                print_error("Нет текущего сообщения. Сначала введите или загрузите сообщение.")
            else:
                save_message_to_file(message, BASE_DIR)
        elif choice == 'c':
            if signature is None:
                print_error("Нет текущей подписи. Сначала подпишите сообщение в главном меню (пункт 2).")
            else:
                save_signature_to_file(signature[0], signature[1], BASE_DIR)
        elif choice == 'd':
            msg, sig, pub = interactive_load_verification_data(gost)
            if msg is None or sig is None or pub is None:
                continue
            print_info(f"Проверка подписи для сообщения: {msg}")
            result = gost.verify(msg, sig, pub, verbose=True)
            if result:
                print_success("Проверка пройдена: подпись верна!")
            else:
                print_error("Проверка не пройдена: подпись неверна!")
        elif choice == 'e':
            pub = load_public_key_from_file(os.path.join(BASE_DIR, "public_key.txt"))
            if pub:
                public_key = pub
                print_info("Открытый ключ загружен.")
        elif choice == 'f':
            filepath = input(Colors.CYAN + "   Введите путь к файлу сообщения: " + Colors.END).strip()
            if not filepath:
                print_error("Путь не может быть пустым.")
                continue
            msg = load_message_from_file(filepath)
            if msg:
                message = msg
                print_info(f"Текущее сообщение: {message}")
        elif choice == 'g':
            filepath = input(Colors.CYAN + "   Введите путь к файлу подписи: " + Colors.END).strip()
            if not filepath:
                print_error("Путь не может быть пустым.")
                continue
            sig = load_signature_from_file(filepath)
            if sig:
                signature = sig
                print_info(f"Текущая подпись: (r, s) = {signature}")
        else:
            print_error("Неверный выбор. Введите a-g или 0.")

    return private_key, public_key, message, signature

def print_main_menu():
    print(Colors.BOLD + Colors.YELLOW + "\n" + "-" * 70 + Colors.END)
    print(Colors.BOLD + Colors.CYAN + "                         ГЛАВНОЕ МЕНЮ".center(70) + Colors.END)
    print(Colors.BOLD + Colors.YELLOW + "-" * 70 + Colors.END)
    print(f" {Colors.GREEN}1.{Colors.END} Сгенерировать ключевую пару (автосохранение)")
    print(f" {Colors.GREEN}2.{Colors.END} Подписать сообщение (ввод с клавиатуры, автосохранение)")
    print(f" {Colors.GREEN}3.{Colors.END} Проверить подпись (по текущим данным в памяти)")
    print(f" {Colors.GREEN}4.{Colors.END} Проверить подпись (изменённое сообщение, по памяти)")
    print(f" {Colors.GREEN}5.{Colors.END} Показать информацию")
    print(f" {Colors.GREEN}6.{Colors.END} О программе (ГОСТ и формулы)")
    print(f" {Colors.GREEN}7.{Colors.END} Управление файлами (сохранить/загрузить/проверить)")
    print(f" {Colors.GREEN}0.{Colors.END} Выход")
    print(Colors.BOLD + Colors.YELLOW + "-" * 70 + Colors.END)
    print(Colors.MAGENTA + " Подсказка: 1 -> 2 -> 3 (верна) -> 4 (неверна)" + Colors.END)
    print(Colors.MAGENTA + " Для загрузки произвольных файлов используйте 7 -> f (сообщение) / g (подпись)" + Colors.END)
    print(Colors.BOLD + Colors.YELLOW + "-" * 70 + Colors.END)

def show_about():
    print_header("О СТАНДАРТЕ ГОСТ Р 34.10-2012")
    print("""
    [i] Российский стандарт электронной подписи на эллиптических кривых.
    [i] Используемые параметры (вариант 1):
        p = 10711, a = 236, b = 757, q = 5441
    [i] Базовая точка G найдена автоматически (порядок q).
    [i] Упрощённая хэш-функция: разбиение на блоки l = floor(log2 q) бит,
        сложение по модулю 2^l, затем e = результат mod q (0→1).
    [i] Алгоритм полностью соответствует ГОСТ Р 34.10-2012.
    """)
    input("\n   Нажмите Enter для продолжения...")

def main():
    print_logo()
    print_info(f"Рабочая папка для файлов: {BASE_DIR}")
    p, a, b, q = 10711, 236, 757, 5441
    print_info(f"Параметры: p={p}, a={a}, b={b}, q={q}")
    try:
        gost = GOST3410_2012(p, a, b, q)
        print_success("Система готова к работе")
        time.sleep(1)
    except Exception as e:
        print_error(f"Ошибка инициализации: {e}")
        return

    private_key = None
    public_key = None
    message = None
    signature = None

    while True:
        print_main_menu()
        if private_key:
            print_info(f"Состояние: ключи OK | сообщение: {'OK' if message else 'нет'} | подпись: {'OK' if signature else 'нет'}")
        else:
            print_warning("Состояние: ключи не сгенерированы")
        print()

        choice = input(Colors.BOLD + "   Выберите действие [0-7]: " + Colors.END).strip()
        print()

        if choice == '0':
            print_info("Завершение работы. До свидания!")
            sys.exit(0)

        elif choice == '1':
            try:
                private_key, public_key = gost.generate_keypair(verbose=True)
                print_success("Ключевая пара сгенерирована!")
                save_keys_to_files(private_key, public_key, BASE_DIR)
                input("\n   Нажмите Enter...")
            except Exception as e:
                print_error(f"Ошибка: {e}")
                input("\n   Нажмите Enter...")

        elif choice == '2':
            if private_key is None:
                print_error("Сначала сгенерируйте ключи (пункт 1)")
                input("\n   Нажмите Enter...")
                continue
            print_info("Введите сообщение для подписи:")
            message = input(Colors.CYAN + "   Сообщение: " + Colors.END).strip()
            if not message:
                print_error("Сообщение не может быть пустым")
                input("\n   Нажмите Enter...")
                continue
            try:
                signature = gost.sign(message, private_key, verbose=True)
                print_success("Подпись создана!")
                save_message_to_file(message, BASE_DIR)
                save_signature_to_file(signature[0], signature[1], BASE_DIR)
                input("\n   Нажмите Enter...")
            except Exception as e:
                print_error(f"Ошибка: {e}")
                signature = None
                input("\n   Нажмите Enter...")

        elif choice == '3':
            if private_key is None or message is None or signature is None:
                print_error("Сначала выполните пункты 1 и 2 (данные в памяти отсутствуют).")
                print_info("Используйте пункт 7 -> d для проверки подписи из файлов.")
                input("\n   Нажмите Enter...")
                continue
            result = gost.verify(message, signature, public_key, verbose=True)
            if result:
                print_success("Проверка пройдена: подпись верна!")
            else:
                print_error("Проверка не пройдена: подпись неверна!")
            input("\n   Нажмите Enter...")

        elif choice == '4':
            if private_key is None or message is None or signature is None:
                print_error("Сначала выполните пункты 1 и 2 (данные в памяти отсутствуют).")
                input("\n   Нажмите Enter...")
                continue
            corrupted = message + " (ИЗМЕНЕНО)"
            print_info(f"Оригинал: {message}")
            print_info(f"Изменённое сообщение: {corrupted}")
            result = gost.verify(corrupted, signature, public_key, verbose=True)
            if not result:
                print_success("Ожидаемый результат: подпись неверна для изменённого сообщения")
            else:
                print_error("КРИТИЧЕСКАЯ ОШИБКА: подпись верна для изменённого сообщения!")
            input("\n   Нажмите Enter...")

        elif choice == '5':
            print_header("ИНФОРМАЦИЯ О СИСТЕМЕ")
            print(f"   Кривая:     y² = x³ + {gost.curve.a}x + {gost.curve.b} mod {gost.curve.p}")
            print(f"   Порядок q:  {gost.q}")
            print(f"   Базовая точка G: {gost.G}")
            if private_key:
                print(f"\n   [Секретный ключ] d = {private_key}")
                print(f"   [Открытый ключ] Q = {public_key}")
                if message:
                    print(f"   [Сообщение] {message}")
                if signature:
                    print(f"   [Подпись] (r, s) = {signature}")
            else:
                print(f"\n   {Colors.YELLOW}[!] Ключи не сгенерированы{Colors.END}")
            input("\n   Нажмите Enter...")

        elif choice == '6':
            show_about()

        elif choice == '7':
            private_key, public_key, message, signature = file_operations_menu(
                gost, private_key, public_key, message, signature
            )

        else:
            print_error("Неверный выбор. Введите число от 0 до 7.")
            input("\n   Нажмите Enter...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n" + Colors.YELLOW + "Программа прервана пользователем" + Colors.END)
        sys.exit(0)
    except Exception as e:
        print_error(f"Неожиданная ошибка: {e}")
        sys.exit(1)