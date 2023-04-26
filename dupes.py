import os
import hashlib
import time
import threading
from collections import defaultdict
from pathlib import Path
from tkinter import Tk, Label, Button, filedialog, messagebox, StringVar, Toplevel, Radiobutton, ttk, Frame, BooleanVar, Checkbutton


def obtener_hash(file_path, chunk_size=1024):
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()

def escanear_archivos(folder_paths, update_progress_callback):
    archivo_hash = defaultdict(list)
    total_files = 0

    for folder_path in folder_paths:
        for root, _, files in os.walk(folder_path):
            total_files += len(files)

    processed_files = 0
    for folder_path in folder_paths:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = Path(root) / file
                file_md5 = obtener_hash(file_path)
                archivo_hash[file_md5].append(file_path)
                processed_files += 1
                update_progress_callback(processed_files, total_files)

    return archivo_hash

def analizar_duplicados_o_unicos(archivo_hash, buscar_duplicados):
    resultado = {}
    
    for key, value in archivo_hash.items():
        if buscar_duplicados and len(value) > 1:
            resultado[key] = value
        elif not buscar_duplicados and len(value) == 1:
            resultado[key] = value
    
    return resultado

class App:
    def debug(self, msg):
        if self.debug_mode.get():
            print(f"[DEBUG] {msg}")

    def __init__(self, master):
        self.completed = False
        self.progress_updated = 0
        self.current_progress = (0, 0)
        self.start_time = 0
        self.master = master
        master.title("Analizador de Archivos")

        top_frame = Frame(master)
        top_frame.pack(side="top", padx=10, pady=10)

        treeview_frame = Frame(master)
        treeview_frame.pack(side="top", padx=10)

        bottom_frame = Frame(master)
        bottom_frame.pack(side="top", padx=10, pady=10)

        self.label = Label(top_frame, text="Selecciona las carpetas para analizar:")
        self.label.pack(side="left")

        self.treeview = ttk.Treeview(treeview_frame, selectmode="browse", height=10)
        self.treeview.pack(side="left")
        self.treeview.column("#0", width=400)
        self.treeview.heading("#0", text="Carpeta")

        self.scrollbar = ttk.Scrollbar(treeview_frame, orient="vertical", command=self.treeview.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.treeview.config(yscrollcommand=self.scrollbar.set)

        self.agregar_carpeta_button = Button(bottom_frame, text="Agregar carpeta", command=self.agregar_carpeta)
        self.agregar_carpeta_button.pack(side="left")

        self.eliminar_carpeta_button = Button(bottom_frame, text="Eliminar carpeta seleccionada", command=self.eliminar_carpeta)
        self.eliminar_carpeta_button.pack(side="left")

        self.buscar_var = StringVar(master)
        self.buscar_var.set("Duplicados")
        
        self.radiobutton_duplicados = Radiobutton(bottom_frame, text="Duplicados", variable=self.buscar_var, value="Duplicados")
        self.radiobutton_duplicados.pack(side="left")

        self.radiobutton_unicos = Radiobutton(bottom_frame, text="Únicos", variable=self.buscar_var, value="Únicos")
        self.radiobutton_unicos.pack(side="left")

        self.buscar_button = Button(bottom_frame, text="Analizar", command=self.buscar)
        self.buscar_button.pack(side="left")

        self.barra_progreso = ttk.Progressbar(master, mode="determinate")
        self.barra_progreso.pack(fill="x", padx=10, pady=10)
        self.progress_label = Label(master)
        self.progress_label.pack(fill="x", padx=10, pady=0)

        # Crear una variable para controlar el modo de depuración
        self.debug_mode = BooleanVar()
        self.debug_mode.set(False)

        # Crear un Checkbutton para activar/desactivar el modo de depuración
        self.debug_checkbutton = Checkbutton(master, text="Modo depuración", variable=self.debug_mode, bg=dark_bg_color, fg=dark_fg_color)
        self.debug_checkbutton.pack(side="right", padx=10, pady=10)


    def agregar_carpeta(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.treeview.insert('', 'end', text=folder_path)
            self.debug(f"Se agregó la carpeta: {folder_path}")

    def eliminar_carpeta(self):
        seleccionado = self.treeview.selection()
        if seleccionado:
            folder_path = self.treeview.item(seleccionado)['text']
            self.treeview.delete(seleccionado)
            self.debug(f"Se eliminó la carpeta: {folder_path}")

    def buscar(self):
        folder_paths = self.obtener_directorios()
        
        if not folder_paths:
            messagebox.showerror("Error", "Selecciona al menos un directorio para analizar.")
            return

        # Reinicia la barra de progreso
        self.barra_progreso["value"] = 0
        self.start_time = time.time()

        # Crea un hilo para realizar la búsqueda y comienza el hilo
        search_thread = threading.Thread(target=self.buscar_dupes, args=(folder_paths,))
        search_thread.start()
         # Iniciar las actualizaciones de progreso cada segundo
        self.update_progress_every_second()
        

    def buscar_dupes(self, folder_paths):
        archivo_hash = escanear_archivos(folder_paths, self.update_progress)
        buscar_duplicados = self.buscar_var.get() == "Duplicados"
        resultado = analizar_duplicados_o_unicos(archivo_hash, buscar_duplicados)
        self.mostrar_resultados(resultado, buscar_duplicados)

    def obtener_directorios(self):
            return [self.treeview.item(child)['text'] for child in self.treeview.get_children()]
        
    def update_progress_every_second(self):
        processed_files, total_files = self.current_progress
        if total_files == 0:
            progress = 0
        else:
            progress = int((processed_files / total_files) * 100)
        self.barra_progreso["value"] = progress

        # Calcular el tiempo transcurrido y el tiempo estimado restante
        elapsed_time = time.time() - self.start_time
        if processed_files > 0:
            time_per_file = elapsed_time / processed_files
            remaining_files = total_files - processed_files
            estimated_time_remaining = remaining_files * time_per_file
        else:
            estimated_time_remaining = 0

        # Formatear el tiempo transcurrido y el tiempo estimado restante
        elapsed_time_str = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
        estimated_time_remaining_str = time.strftime("%H:%M:%S", time.gmtime(estimated_time_remaining))

        # Actualizar el texto en la etiqueta de progreso
        self.progress_label["text"] = f"Archivos analizados: {processed_files}/{total_files} - Tiempo transcurrido: {elapsed_time_str} - Tiempo estimado restante: {estimated_time_remaining_str}"

        self.master.update_idletasks()

        # Continuar actualizando cada segundo solo si la tarea no está completa
        if not self.completed:
            self.master.after(1000, self.update_progress_every_second)

    def update_progress(self, processed_files, total_files):
        self.current_progress = (processed_files, total_files)
        current_time = time.time()
        if current_time - self.progress_updated >= 1:
            progress = int((processed_files / total_files) * 100)
            self.barra_progreso["value"] = progress

            # Calcular el tiempo transcurrido y el tiempo estimado restante
            elapsed_time = current_time - self.start_time
            if processed_files > 0:
                time_per_file = elapsed_time / processed_files
                remaining_files = total_files - processed_files
                estimated_time_remaining = remaining_files * time_per_file
            else:
                estimated_time_remaining = 0

            # Formatear el tiempo transcurrido y el tiempo estimado restante
            elapsed_time_str = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
            estimated_time_remaining_str = time.strftime("%H:%M:%S", time.gmtime(estimated_time_remaining))

            # Actualizar el texto en la etiqueta de progreso
            self.progress_label["text"] = f"Archivos analizados: {processed_files}/{total_files} - Tiempo transcurrido: {elapsed_time_str} - Tiempo estimado restante: {estimated_time_remaining_str}"

            self.master.update_idletasks()
            self.progress_updated = current_time
            if processed_files == total_files:
                self.completed = True
            else:
                self.completed = False

    def mostrar_resultados(self, resultado, buscar_duplicados):
        resultados_ventana = Toplevel(self.master)
        resultados_ventana.title("Resultados")

        if buscar_duplicados:
            texto = "Archivos duplicados:"
        else:
            texto = "Archivos únicos:"

        label = Label(resultados_ventana, text=texto)
        label.pack()

        resultados_treeview = ttk.Treeview(resultados_ventana, selectmode="browse", height=20)
        resultados_treeview.pack()
        resultados_treeview.column("#0", width=600)
        resultados_treeview.heading("#0", text="Archivo")

        scrollbar = ttk.Scrollbar(resultados_ventana, orient="vertical", command=resultados_treeview.yview)
        scrollbar.pack(side="right", fill="y")
        resultados_treeview.config(yscrollcommand=scrollbar.set)

        for file_paths in resultado.values():
            for file_path in file_paths:
                resultados_treeview.insert('', 'end', text=str(file_path))

        eliminar_archivos_button = Button(resultados_ventana, text="Eliminar archivo(s) seleccionado(s)", command=lambda: self.eliminar_archivos(resultados_treeview))
        eliminar_archivos_button.pack()

        close_button = Button(resultados_ventana, text="Cerrar", command=resultados_ventana.destroy)
        close_button.pack()

    def eliminar_archivos(self, resultados_treeview):
        seleccionado = resultados_treeview.selection()
        if seleccionado:
            file_path = resultados_treeview.item(seleccionado)['text']
            try:
                os.remove(file_path)
                resultados_treeview.delete(seleccionado)
            except OSError as e:
                messagebox.showerror("Error", f"No se pudo eliminar el archivo '{file_path}': {e}")

if __name__ == "__main__":
    root = Tk()
    root.geometry("800x600")
    # Establecer el tema oscuro para la aplicación
    style = ttk.Style()
    style.theme_use("clam")

    # Colores oscuros para el fondo y el texto
    dark_bg_color = "#333333"
    dark_fg_color = "#ffffff"

    # Configurar los colores y estilos de los widgets
    style.configure("TLabel", background=dark_bg_color, foreground=dark_fg_color)
    style.configure("TButton", background=dark_bg_color, foreground=dark_fg_color, bordercolor=dark_fg_color)
    style.configure("TRadiobutton", background=dark_bg_color, foreground=dark_fg_color, selectcolor=dark_bg_color)
    style.configure("TProgressbar", background=dark_fg_color)
    style.configure("Treeview", background=dark_bg_color, foreground=dark_fg_color, fieldbackground=dark_bg_color)
    style.configure("Treeview.Heading", background=dark_fg_color, foreground=dark_bg_color)

    root.configure(background=dark_bg_color)

    app = App(root)

    root.mainloop()
