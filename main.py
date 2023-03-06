__author__ = 'https://github.com/password123456/'
__version__ = '1.0.0-20230306'

import os
import sys
import platform
import time
import requests
import hashlib
import argparse
import uuid
import netifaces
import csv
import pefile

from datetime import datetime
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from concurrent.futures import ProcessPoolExecutor, as_completed

# Configurations
SCAN_EXTENSIONS = ['.exe', '.sys', '.dll']

EXCLUDED_DIRECTORIES = ['Windows', 'ProgramData']
EXCLUDED_DIRECTORIES = [subject.lower() for subject in EXCLUDED_DIRECTORIES]

TRUSTED_CODESIGN_SUBJECTS = ['Microsoft Windows', 'Microsoft Corporation', 'Microsoft Code Signing PCA', 'Microsoft Windows Production PCA']
TRUSTED_CODESIGN_SUBJECTS = [subject.lower() for subject in TRUSTED_CODESIGN_SUBJECTS]

_home_path = f'{os.getcwd()}'

_engine_file = f'{_home_path}/engine.csv'
_result_logs = f'{_home_path}/output/{datetime.today().strftime("%Y%m%d")}_scan.log'


class Bcolors:
    Black = '\033[30m'
    Red = '\033[31m'
    Green = '\033[32m'
    Yellow = '\033[33m'
    Blue = '\033[34m'
    Magenta = '\033[35m'
    Cyan = '\033[36m'
    White = '\033[37m'
    Endc = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def download_engine():
    _url = f'https://bazaar.abuse.ch/export/csv/cscb/'
    _header = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36',
               'Connection': 'keep-alive'}
    try:
        with open(_engine_file, 'wb') as f:
            r = requests.get(_url, headers=_header, stream=True)
            download_file_length = r.headers.get('Content-Length')
            print(f'{Bcolors.Green} Downloading: {_engine_file} / {(float(download_file_length) / (1024.0 * 1024.0)):.2f} MB {Bcolors.Endc}')

            if download_file_length is None:
                f.write(r.content)
            else:
                dl = 0
                total_length = int(download_file_length)
                start = time.perf_counter()
                for data in r.iter_content(chunk_size=8092):
                    dl += len(data)
                    f.write(data)
                    done = int(100 * dl / total_length)
                    print(f'[{">" * done}{" " * (100 - done)}] {total_length}/{dl} ({done}%) - {(time.perf_counter() - start):.2f} seconds ', end='\r')

        # Check Downloaded File
        if os.path.isfile(_engine_file):
            with open(_engine_file, 'rb') as f:
                file_read = f.read()
                file_hash = hashlib.sha256(file_read).hexdigest()
                file_info = f'===> Extracted Size: {int(os.path.getsize(_engine_file)) / (1024.0 * 1024.0):.2f} MB\n===> Hash(SHA-256) : {file_hash}\n'

                print(f'\n\n{Bcolors.Green}===> Update Success: {_engine_file} {Bcolors.Endc}')
                print(f'{Bcolors.Green}{file_info}{Bcolors.Endc}')
        else:
            print(f'{Bcolors.Yellow}[-] {_engine_file} not found. {Bcolors.Endc}')
            sys.exit(1)

    except Exception as e:
        print(f'{Bcolors.Yellow}- ::Exception:: Func:[{download_engine.__name__}] Line:[{sys.exc_info()[-1].tb_lineno}] [{type(e).__name__}] {e}{Bcolors.Endc}')


def raw_count(filename):
    n = 0
    mode = 'r'
    with open(filename, mode, encoding='utf-8') as f:
        for line in f:
            if not line.startswith('#'):
                n = n + 1
    return n


def csv_decomment(csvfile):
    for row in csvfile:
        raw = row.split('#')[0].strip()
        if raw:
            yield row


def get_engine_last_updated_date(filename):
    mode = 'r'
    with open(filename, mode, encoding='utf-8') as file:
        for line in file:
            if 'Last updated' in line:
                line = line.replace('#', '')
                line = line.lstrip().strip('\n')
                line = line.split(' ')
                line = line[2:5]
                line = ' '.join(line)
                break
    return line


def hash_exists_in_database(serial_number, thumbprint):
    mode = 'r'
    with open(_engine_file, mode, encoding='utf-8') as database:
        reader = csv.DictReader(csv_decomment(database), delimiter=',', lineterminator='\n', skipinitialspace=True)
        for row in reader:
            if str(serial_number) in str(row['serial_number']):
                if str(thumbprint) in str(row['thumbprint']):
                    return True
    return False


def scan_logs(_contents):
    output_dir = f'{_home_path}/output'
    mode = 'w'
    if os.path.exists(output_dir):
        if os.path.exists(_result_logs):
            mode = 'a'
    else:
        mode = 'w'
        os.makedirs(output_dir)
    with open(_result_logs, mode) as f:
        f.write(f'{_contents}')


def is_digitally_signed(_file_name):
    try:
        pe = pefile.PE(_file_name)
        address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress
        if address != 0:
            return True
        else:
            return False
    except pefile.PEFormatError as e:
        return False


def get_digitally_signed_info(_file_name):
    ret_signature_hash = ''
    ret_serial_number = ''
    ret_thumbprint = ''
    ret_subject_name = ''
    ret_issuer_name = ''
    is_sha256_verified = False

    try:
        pe = pefile.PE(_file_name)
        if hex(pe.DOS_HEADER.e_magic) == '0x5a4d':
            address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress
            size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size

            if size > 0:
                with open(_file_name, 'rb') as fh:
                    fh.seek(address)
                    thesig = fh.read(size)

                signature = cms.ContentInfo.load(thesig[8:])
                for cert in signature['content']['certificates']:
                    x509_pem_cert = x509.load_der_x509_certificate(cert.dump(), default_backend())
                    subject_name = x509_pem_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.lower()
                    if not any(subject_name.startswith(x) for x in TRUSTED_CODESIGN_SUBJECTS):
                        if x509_pem_cert.signature_hash_algorithm.name.lower() == 'sha256':
                            is_sha256_verified = True
                            ret_subject_name = x509_pem_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                            ret_issuer_name = x509_pem_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                            ret_signature_hash = x509_pem_cert.signature_hash_algorithm.name
                            ret_thumbprint = x509_pem_cert.fingerprint(hashes.SHA256()).hex()
                            ret_serial_number = hex(x509_pem_cert.serial_number)[2:].zfill(32)

                            return True, ret_signature_hash, ret_serial_number, ret_thumbprint, ret_subject_name, ret_issuer_name

                if not is_sha256_verified:
                    return False, ret_signature_hash, ret_serial_number, ret_thumbprint, ret_subject_name, ret_issuer_name
    except (pefile.PEFormatError, AttributeError):
        return False, ret_signature_hash, ret_serial_number, ret_thumbprint, ret_subject_name, ret_issuer_name


def has_valid_extension(_file_name):
    if _file_name.endswith(tuple(SCAN_EXTENSIONS)):
        return True
    else:
        return False


def check_file_size(_file_name):
    # 10MB = '10485760'
    limit = 10485760

    f = os.stat(_file_name).st_size
    if f <= limit:
        return True
    else:
        return False


def get_creation_date(_file_name):
    if platform.system() == 'Windows':
        result = os.path.getctime(_file_name)
    else:
        result = os.path.getmtime(_file_name)
    return datetime.fromtimestamp(result).strftime('%Y-%m-%d %H:%M:%S')


def get_modified_date(_file_name):
    result = os.path.getmtime(_file_name)
    return datetime.fromtimestamp(result).strftime('%Y-%m-%d %H:%M:%S')


def get_hostname():
    return platform.node()


def get_os_version():
    return platform.system()


def get_ip_address():
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET]
    gateway_ip, interface = default_gateway[0], default_gateway[1]
    iface = netifaces.ifaddresses(interface)
    local_ip = iface[netifaces.AF_INET][0]['addr']
    return local_ip


def create_job_id():
    return uuid.uuid4()


def check_engine():
    if os.path.exists(_engine_file):
        engine_modified_time = os.stat(_engine_file).st_mtime
        numof_ymd_today = datetime.today().strftime('%Y%m%d')
        numof_ymd_engine_file_date = datetime.fromtimestamp(engine_modified_time).strftime('%Y%m%d')

        if not(int(numof_ymd_engine_file_date) == int(numof_ymd_today)):
            get_download = False
        else:
            get_download = True

        if not get_download:
            print(f'{Bcolors.Yellow}- Updating Engine Signatures.{Bcolors.Endc}')
            download_engine()
        else:
            print(f'{Bcolors.Yellow}- Up2date Engine   : ^_^V {Bcolors.Endc}')
    else:
        print(f'{Bcolors.Yellow}- Updating Engine Signatures.{Bcolors.Endc}')
        download_engine()


def scan_file(_f_file_name):
    scan_result = ''
    if has_valid_extension(_f_file_name):
        if check_file_size(_f_file_name):
            if is_digitally_signed(_f_file_name):
                file_result, file_signature_hash, file_serial_number, file_thumbprint, file_subject_cn, file_issuer_cn = get_digitally_signed_info(_f_file_name)
                if file_result:
                    if hash_exists_in_database(file_serial_number, file_thumbprint):
                        scan_result = f'{_f_file_name}|{file_signature_hash}|{file_serial_number}|{file_thumbprint}|{file_subject_cn}|{file_issuer_cn}|{get_creation_date(_f_file_name)}|{get_modified_date(_f_file_name)}'
            return scan_result


def scan_directory(scan_path):
    log_ip_address = get_ip_address()
    log_hostname = get_hostname()
    log_scan_id = create_job_id()
    log_os_version = get_os_version()

    submitted_file_count = 0
    infected_file_count = 0
    infected_file_list = ''

    scan_start_time = time.perf_counter()

    with ProcessPoolExecutor(max_workers=5) as executor:
        for subdir, dirs, files in os.walk(scan_path):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRECTORIES]
            for file in files:
                try:
                    file_path = os.path.realpath(os.path.join(subdir, file))
                    result = [executor.submit(scan_file, file_path)]
                    for future in as_completed(result, timeout=10):
                        try:
                            result_str = future.result()
                            submitted_file_count += 1
                            scan_duration_time = time.perf_counter() - scan_start_time

                            if result_str:
                                infected_file_count += 1
                                infected_file_list += f' - {file_path}\n'

                                print(f'[{datetime.strftime(datetime.utcfromtimestamp(scan_duration_time), "%H:%M:%S.%f")}] '
                                      f'({submitted_file_count} scanned) {Bcolors.Blue}[infected]{Bcolors.Endc} {file_path}')

                                infected_file_info = result_str.split("|")
                                contents = (
                                    f'datetime="{datetime.today().strftime("%Y-%m-%d %H:%M:%S")}",'
                                    f'scan_id="{log_scan_id}",'
                                    f'os_version="{log_os_version}",'
                                    f'hostname="{log_hostname}",'
                                    f'ip_address="{log_ip_address}",'
                                    f'infected_file="{infected_file_info[0]}",'
                                    f'signature_hash="{infected_file_info[1]}",'
                                    f'serial_number="{infected_file_info[2]}",'
                                    f'thumbprint="{infected_file_info[3]}",'
                                    f'subject_name="{infected_file_info[4]}",'
                                    f'issuer_name="{infected_file_info[5]}",'
                                    f'file_created_at="{infected_file_info[6]}",'
                                    f'file_modified_at="{infected_file_info[7]}"\n'
                                )
                                scan_logs(contents)
                            else:
                                print(f'[{datetime.strftime(datetime.utcfromtimestamp(scan_duration_time), "%H:%M:%S.%f")}] '
                                      f'({submitted_file_count} scanned) {Bcolors.Yellow}[O.K]{Bcolors.Endc} {file_path}')
                        except TimeoutError:
                            pass
                except Exception as e:
                    # print(e)
                    continue

    if infected_file_count >= 1:
        print(f'\x1b[0;43;43m Scan Completed.! \x1b[0m \n- O.M.G... \x1b[0;42;42m [{infected_file_count}] \x1b[0m files found.')
        print(f'\n[RESULT]\n{infected_file_list}')
        print(f'>>>>> See "{_result_logs}"\n')
    else:
        _contents = f'datetime="{datetime.today().strftime("%Y-%m-%d %H:%M:%S")}",scan_id="{log_scan_id}",os="{log_os_version}",' \
                    f'hostname="{log_hostname}",ip="{log_ip_address}",infected_file="None"\n'
        scan_logs(_contents)
        print(f'\n')
        print(f'\x1b[0;43;43m Scan Completed.! \x1b[0m \n- No infected file found.! happy happy:)\n')


def main():
    print(f'\n')
    print(f'{Bcolors.Green}▌║█║▌│║▌│║▌║▌█║ {Bcolors.Red}CertVerify{Bcolors.White} v{__version__}{Bcolors.Green} ▌│║▌║▌│║║▌█║▌║█{Bcolors.Endc}\n')
    opt = argparse.ArgumentParser()
    opt.add_argument('--path', help='ex) /home/download')
    opt.add_argument('--update', action='store_true', help='Untrusted Certificates Engine Update')

    if len(sys.argv) < 1:
        opt.print_help()
        sys.exit(1)
    else:
        options = opt.parse_args()
        print(f'File scanner for files signed with leaked or untrusted certificates.\n')
        print(f'- Run time: {datetime.today().strftime("%Y-%m-%d %H:%M:%S")}')
        print('- For questions contact github.com/password123456\t\t')
        print('\n')

        if options.path:
            _scan_path = os.path.abspath(options.path)
            print(f'{Bcolors.Green}------------------------------------->{Bcolors.Endc}\n')
            check_engine()
            print(f'- Engine Updated   : {get_engine_last_updated_date(_engine_file)}')
            print(f'- Total Signatures : {raw_count(_engine_file)}')
            print(f'-{Bcolors.Green} O.K Here We go.!{Bcolors.Endc}')
            scan_directory(_scan_path)

        elif options.update:
            print(f'{Bcolors.Green}——————————————————>{Bcolors.Endc}\n')
            check_engine()
            print(f'- Engine Updated   : {get_engine_last_updated_date(_engine_file)}')
            print(f'- Total Signatures : {raw_count(_engine_file)}')
        else:
            opt.print_help()
            sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f'{Bcolors.Yellow}- ::Exception:: Func:[{__name__.__name__}] Line:[{sys.exc_info()[-1].tb_lineno}] [{type(e).__name__}] {e}{Bcolors.Endc}')
