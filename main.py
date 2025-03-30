import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

class UDPClient:
    def __init__(self, ip, port, display_callback):
        self.server_address = (ip, port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Configura o socket para enviar para um endereço padrão
        self.socket.connect(self.server_address)
        # Define timeout para evitar bloqueio infinito no recv
        self.socket.settimeout(1.0)
        self.display_callback = display_callback
        self.listening = True
        self.listener_thread = threading.Thread(target=self.listen, daemon=True)
        self.listener_thread.start()
        self.display_callback("Conectado ao servidor UDP")

    def send_message(self, message):
        self.socket.send(message.encode())

    def listen(self):
        while self.listening:
            try:
                data = self.socket.recv(1024)
                if data:
                    self.display_callback(f"Servidor (UDP): {data.decode()}")
            except socket.timeout:
                # Timeout permite verificar a flag de encerramento
                continue
            except Exception as e:
                if self.listening:
                    self.display_callback(f"Erro UDP: {e}")
                break

    def close(self):
        self.listening = False
        # Aguarda a thread encerrar (com timeout para evitar travar a aplicação)
        self.listener_thread.join(timeout=2)
        self.socket.close()

class TCPClient:
    def __init__(self, ip, port, display_callback):
        self.server_address = (ip, port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.display_callback = display_callback
        try:
            self.socket.connect(self.server_address)
            self.display_callback("Conectado ao servidor TCP")
        except socket.error as e:
            messagebox.showerror("Erro de Conexão TCP", str(e))
            raise e

        self.listening = True
        self.listener_thread = threading.Thread(target=self.listen, daemon=True)
        self.listener_thread.start()

    def send_message(self, message):
        self.socket.sendall(message.encode())

    def listen(self):
        while self.listening:
            try:
                data = self.socket.recv(1024)
                if data:
                    self.display_callback(f"Servidor (TCP): {data.decode()}")
                else:
                    self.display_callback("Conexão encerrada pelo servidor.")
                    break
            except Exception as e:
                if self.listening:
                    self.display_callback(f"Erro TCP: {e}")
                break

    def close(self):
        self.listening = False
        self.listener_thread.join(timeout=2)
        self.socket.close()

class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Chat Cliente UDP/TCP")
        self.master.geometry("400x500")
        self.connection_type = tk.StringVar(value="UDP")
        self.client = None  # Será uma instância de UDPClient ou TCPClient
        
        self.setup_ui()
        
    def setup_ui(self):
        # Configuração de IP e Porta
        frame_top = tk.Frame(self.master)
        frame_top.pack(pady=10)
        tk.Label(frame_top, text="Endereço IP:").grid(row=0, column=0, sticky='w')
        self.ip_entry = tk.Entry(frame_top, width=15)
        self.ip_entry.grid(row=0, column=1)
        self.ip_entry.insert(0, "127.0.0.1")
        tk.Label(frame_top, text="Porta:").grid(row=0, column=2, sticky='w')
        self.port_entry = tk.Entry(frame_top, width=5)
        self.port_entry.grid(row=0, column=3)
        self.port_entry.insert(0, "8080")
        
        # Escolha do protocolo e botão de conectar
        frame_middle = tk.Frame(self.master)
        frame_middle.pack(pady=5)
        self.udp_radio = tk.Radiobutton(frame_middle, text="UDP", variable=self.connection_type, value="UDP")
        self.udp_radio.grid(row=0, column=0)
        self.tcp_radio = tk.Radiobutton(frame_middle, text="TCP", variable=self.connection_type, value="TCP")
        self.tcp_radio.grid(row=0, column=1)
        self.connect_button = tk.Button(frame_middle, text="Conectar", command=self.connect_server)
        self.connect_button.grid(row=0, column=2)
        
        # Área de mensagens
        frame_chat = tk.Frame(self.master)
        frame_chat.pack(pady=5, fill=tk.BOTH, expand=True)
        self.text_area = scrolledtext.ScrolledText(frame_chat, state='disabled', height=15, width=50)
        self.text_area.pack(fill=tk.BOTH, expand=True)
        
        # Entrada de mensagem
        frame_bottom = tk.Frame(self.master)
        frame_bottom.pack(pady=5)
        self.entry = tk.Entry(frame_bottom, width=40)
        self.entry.pack(side=tk.LEFT, padx=5)
        self.entry.bind("<Return>", lambda event: self.send_message())
        self.send_button = tk.Button(frame_bottom, text="Enviar", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)
        
    def connect_server(self):
        ip = self.ip_entry.get()
        try:
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("Erro", "Porta inválida.")
            return
        
        if self.client:
            self.client.close()
            self.client = None
            
        if self.connection_type.get() == "UDP":
            try:
                self.client = UDPClient(ip, port, self.display_message)
            except Exception as e:
                messagebox.showerror("Erro UDP", str(e))
        else:
            try:
                self.client = TCPClient(ip, port, self.display_message)
            except Exception as e:
                # Erro já exibido na classe TCPClient
                self.client = None
        
    def send_message(self):
        message = self.entry.get()
        if not message:
            return
        if not self.client:
            messagebox.showerror("Erro", "Conecte-se primeiro ao servidor.")
            return
        try:
            self.client.send_message(message)
            self.display_message(f"Você: {message}")
            self.entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Erro de Envio", str(e))
        
    def display_message(self, message):
        self.text_area.configure(state='normal')
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.configure(state='disabled')
        self.text_area.yview(tk.END)
        
    def close(self):
        if self.client:
            self.client.close()
        self.master.quit()

if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClient(root)
    root.protocol("WM_DELETE_WINDOW", client.close)
    root.mainloop()
