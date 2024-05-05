import os
import platform
import threading
import signal
import time
import hashlib

def detect_os_version():
    #Détecte l'OS et sa version.
    system_info = platform.uname()
    os_name = system_info.system
    os_version = system_info.release
    return os_name, os_version

def read_file_lines(filename):
    #Lire les lignes d'un fichier.
    try:
        with open(filename) as file:
            return set(file.readlines())
    except Exception as e:
        print(f"Error reading file '{filename}': {e}")
        return set()

last_user_list = read_file_lines('/etc/passwd')
last_group_list = read_file_lines('/etc/group')

def watch_user_creation_linux():
    #Surveillance de la création d'un nouvel utilisateur sur Linux.
    global last_user_list
    while True:
        current_user_list = read_file_lines('/etc/passwd')
        new_users = current_user_list - last_user_list
        if new_users:
            for user in new_users:
                user_info = user.split(':')
                new_user_name = user_info[0]
                new_user_id = user_info[2]
                print("New user detected :", new_user_name, new_user_id)
        last_user_list = current_user_list
        time.sleep(3)

def watch_group_creation_linux():
    #Surveillance de la création d'un nouveau groupe sur Linux.
    global last_group_list
    while True:
        current_group_list = read_file_lines('/etc/group')
        new_groups = current_group_list - last_group_list
        if new_groups:
            for group in new_groups:
                group_info = group.split(':')
                new_group_name = group_info[0]
                print("New group detected :", new_group_name)
        last_group_list = current_group_list
        time.sleep(3)

def watch_user_group_addition():
    #Surveillance de l'ajout d'un user dans un groupe
    chemin_fichier = "/etc/group"
    groupes_actuels = {}
    while True:
        with open(chemin_fichier, 'r') as fichier:
            for ligne in fichier:
                elements = ligne.strip().split(':')
                if len(elements) >= 3:
                    groupe = elements[0]
                    utilisateurs = elements[3].split(',') if len(elements) >= 4 else []
                    groupes_actuels[groupe] = utilisateurs
        time.sleep(5)


def watch_password_change_linux():
    #Surveillance du changement de mot de passe d'un user.
    os.system("cp /etc/shadow /tmp/shadow")
    while True:
        diff = os.popen("diff /etc/shadow /tmp/shadow").read()
        if diff:
            print("Mot de passe utilisateur changé : \n", diff)
            print("Date de changement du mot de passe : ", os.popen("date").read())
            os.system("cp /etc/shadow /tmp/shadow")
        time.sleep(3)
        
def watch_new_and_closed_tty_connections():
    # Surveillance de la connexion d'un utilisateur sur Linux.
    last_connections = None
    while True:
        # Exécuter la commande 'who' pour obtenir les connexions utilisateur actuelles
        output = os.popen("who").read()
        current_connections = set(output.splitlines())
        
        # Vérifier s'il y a des connexions précédentes pour éviter d'afficher les connexions existantes lors de la première exécution
        if last_connections is not None:
            # Trouver les nouvelles connexions en comparant avec les dernières connexions
            new_connections = current_connections - last_connections
            for connection in new_connections:
                print("New user connection detected:", connection)
            
            # Trouver les connexions qui ne sont plus présentes en comparant avec les connexions précédentes
            disconnected_connections = last_connections - current_connections
            for connection in disconnected_connections:
                print("User disconnected:", connection)
        
        last_connections = current_connections
        time.sleep(3)

# Function to watch for new SSH keys
def watch_ssh_key_linux():
    # Surveillance de l'ajout d'une clé SSH.
    ssh_dirs = ["/home", "/root"]
    ssh_keys_dict = {}  # Dictionnaire pour stocker les clés SSH déjà rencontrées
    while True:
        for ssh_dir in ssh_dirs:
            for root, _, files in os.walk(ssh_dir):
                for file in files:
                    if file.endswith('.pub'):
                        key_path = os.path.join(root, file)
                        key_content = open(key_path).read()
                        # Vérifier si la clé SSH a déjà été rencontrée
                        if key_content not in ssh_keys_dict:
                            # Si la clé SSH est nouvelle, l'ajouter au dictionnaire
                            ssh_keys_dict[key_content] = key_path
                            # Extraire le nom d'utilisateur de la clé path
                            username = key_path.split('/')[-3]
                            print(f"New SSH key added for user {username}: {key_content}")
        time.sleep(3)


# Function to watch for SSH logins
def watch_ssh_login_linux():
    while True:
        ssh_log_old = os.popen("journalctl -u sshd.service | grep 'session opened'").read()
        nb_lines = len(ssh_log_old.splitlines())
        time.sleep(1)
        ssh_log_new = os.popen("journalctl -u sshd.service | grep 'session opened'").read()
        nb_lines_new = len(ssh_log_new.splitlines())
        if nb_lines_new > nb_lines:
            print("New SSH connection detected, testing IP address...")
            user_info = os.popen("journalctl -u sshd.service | grep 'session opened'  | tail -n 1").read()
            ip_info = os.popen("journalctl -u sshd.service | grep 'Accepted password for'  | tail -n 2").read()
            if ip_info.split()[10] in open("blacklist.txt").read():
                print("Connection from blacklisted IP address detected: " + ip_info.split()[10])
            else:
                print("Connection allowed for IP address: " + ip_info.split()[10])
        nb_lines = nb_lines_new

# Function to watch for SSH brute force attempts
def watch_ssh_bruteforce_linux():
    count_bruteforce = 0
    nb_lines_old = 0
    old_ssh_success_count = 0
    while True:
        ssh_log_old = os.popen("journalctl -u sshd.service | grep 'Failed password'").read()
        nb_lines = len(ssh_log_old.splitlines())
        ssh_success = os.popen("journalctl -u sshd.service | grep 'session opened'").read()
        ssh_success_count = len(ssh_success.splitlines())
        
        if nb_lines > nb_lines_old:
            count_bruteforce += 1
        else:
            if ssh_success_count > old_ssh_success_count:
                count_bruteforce = 0
                print("SSH login detected, attempts:", ssh_success_count)

        if count_bruteforce == 3:
            print("SSH brute force attempt detected!")
            count_bruteforce = 0
        
        nb_lines_old = nb_lines
        old_ssh_success_count = ssh_success_count


# Function to watch for new open ports
def watch_new_open_port_linux():
    ports_old = os.popen("netstat -tuln > /tmp/ports_old")
    with open("/tmp/ports_old", "r") as f:
        old_ports = set(f.readlines())
    while True:
        os.system("netstat -tuln > /tmp/ports")
        ports_new = os.popen("netstat -tuln > /tmp/ports_new")
        time.sleep(5)
        with open("/tmp/ports_new", "r") as f:
            new_ports = set(f.readlines())
        new_open_ports = new_ports - old_ports
        closed_ports = old_ports - new_ports
        if new_open_ports:
            print("New open port detected!")
            for port in new_open_ports:
                print(port.strip())
        if closed_ports:
            print("Port closed detected!")
            for port in closed_ports:
                print(port.strip())
        old_ports = new_ports


# Function to handle Ctrl+C signal
def signal_handler(sig, frame):
    print("Exiting...")
    exit()

# Main function
def main():
    os_name, os_version = detect_os_version()
    print("Detected OS:", os_name)
    print("Version:", os_version)

    thread_user = threading.Thread(target=watch_user_creation_linux)
    thread_group_creation = threading.Thread(target=watch_group_creation_linux)
    thread_group = threading.Thread(target=watch_user_group_addition)
    thread_password = threading.Thread(target=watch_password_change_linux)
    thread_ssh_key = threading.Thread(target=watch_ssh_key_linux)
    thread_ssh_login = threading.Thread(target=watch_ssh_login_linux)
    thread_ssh_bruteforce = threading.Thread(target=watch_ssh_bruteforce_linux)
    thread_new_open_port = threading.Thread(target=watch_new_open_port_linux)
    thread_new_and_closed_tty = threading.Thread(target=watch_new_and_closed_tty_connections)

    thread_user.start()
    thread_group_creation.start()
    thread_group.start()
    thread_password.start()
    thread_ssh_key.start()
    thread_ssh_login.start()
    thread_ssh_bruteforce.start()
    thread_new_open_port.start()
    thread_new_and_closed_tty.start()

    signal.signal(signal.SIGINT, signal_handler)

    thread_user.join()
    thread_group_creation.join()
    thread_group.join()
    thread_password.join()
    thread_ssh_key.join()
    thread_ssh_login.join()
    thread_ssh_bruteforce.join()
    thread_new_open_port.join()
    thread_new_and_closed_tty.join()

if __name__ == "__main__":
    main()

print("Program finished.")
