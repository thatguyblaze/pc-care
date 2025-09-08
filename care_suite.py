import os
import platform
import subprocess
import time
import shutil
import psutil
import tempfile
import itertools
import threading
import ctypes
import sys
from abc import ABC, abstractmethod
from typing import Dict, Any, Union, Optional

# --- INITIALIZATION ---
from colorama import Fore, Style, init
init(autoreset=True)

# --- UTILITY CLASSES ---

class Spinner:
    """A context-manager-based spinner for long-running tasks."""
    def __init__(self, message: str = "Working..."):
        self._spinner = itertools.cycle(['|', '/', '-', '\\'])
        self._running = False
        self._spinner_thread: Optional[threading.Thread] = None
        self._message = message

    def __enter__(self):
        self._running = True
        self._spinner_thread = threading.Thread(target=self._spin)
        self._spinner_thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._running:
            self._running = False
            if self._spinner_thread:
                self._spinner_thread.join()
            print('\r' + ' ' * (len(self._message) + 5), end='\r')

    def _spin(self):
        while self._running:
            print(f'\r{Fore.YELLOW}{self._message} {next(self._spinner)}', end='')
            time.sleep(0.1)

class SystemUtils:
    """A collection of static utility methods for system interactions."""
    @staticmethod
    def is_admin() -> bool:
        """Check for administrator privileges on Windows."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() == 1
        except AttributeError:
            return False

    @staticmethod
    def clear_screen():
        """Clears the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def run_command_streamed(command: str, title: str) -> bool:
        """Runs a shell command, streams its output, and returns success."""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}--- {title} ---")
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
            while True:
                output = process.stdout.readline()
                if not output and process.poll() is not None:
                    break
                if output:
                    print(f"  {Style.DIM}{output.strip()}")
            rc = process.poll()
            if rc == 0:
                print(f"{Fore.GREEN}✔ {title} completed successfully.")
            else:
                print(f"{Fore.RED}✖ {title} finished with errors (code {rc}).")
            return rc == 0
        except Exception as e:
            print(f"{Fore.RED}✖ An error occurred: {e}")
            return False

# --- CORE OOP STRUCTURE: TOOLS & MENUS ---

class MenuItem(ABC):
    """Abstract base class for any item that can be in a menu."""
    def __init__(self, name: str):
        self.name = name

class Tool(MenuItem):
    """Abstract base class for all tools in the application."""
    def __init__(self, name: str, description: str, long_running: bool = False, dangerous: bool = False):
        super().__init__(name)
        self.description = description
        self.long_running = long_running
        self.dangerous = dangerous

    def confirm_action(self) -> bool:
        """Displays a confirmation prompt for the tool."""
        prompt = f"Run '{self.name}'? ({self.description})"
        while True:
            response = input(f"{Fore.YELLOW}{Style.BRIGHT}{prompt} (y/n): ").lower().strip()
            if response in ['y', 'n']:
                return response == 'y'
            print(f"{Fore.RED}Invalid input. Please enter 'y' or 'n'.")

    @abstractmethod
    def execute(self) -> None:
        """The main execution method for the tool."""
        pass

class Menu(MenuItem):
    """Represents a navigable menu in the application."""
    def __init__(self, name: str, items: Dict[str, MenuItem]):
        super().__init__(name)
        self.items = items

    def display(self) -> None:
        """Displays the menu and handles user interaction."""
        while True:
            App.display_header()
            print(f"  {Fore.CYAN}--- {self.name} ---")
            for key, item in self.items.items():
                color = Fore.YELLOW
                if isinstance(item, Tool):
                    if item.long_running: color = Fore.RED
                    if item.dangerous: color = Fore.MAGENTA
                elif isinstance(item, Menu):
                    color = Fore.CYAN
                print(f"  {color}{key}.{Style.RESET_ALL} {item.name}")
            
            print(f"\n  {Fore.CYAN}M.{Style.RESET_ALL} Return to Previous Menu")
            print(Style.DIM + "=" * 50)
            
            choice = input("Select an option: ").lower()
            if choice == 'm':
                return
            
            selected_item = self.items.get(choice)
            if isinstance(selected_item, Tool):
                selected_item.execute()
                input(f"\n{Style.DIM}Press Enter to continue...")
            elif isinstance(selected_item, Menu):
                selected_item.display()
            else:
                print(f"{Fore.RED}Invalid choice.")
                time.sleep(1)

# --- CONCRETE TOOL IMPLEMENTATIONS ---

class CleanTempFiles(Tool):
    def __init__(self):
        super().__init__("Clean Temp Files", "Deletes temporary files from system and user directories.")
    
    def execute(self) -> None:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}--- {self.name} ---")
        with Spinner("Scanning for temp files..."):
            temp_dirs = [tempfile.gettempdir(), os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "Temp")]
            freed_space = 0
            for temp_dir in temp_dirs:
                if not os.path.exists(temp_dir): continue
                for root, dirs, files in os.walk(temp_dir, topdown=False):
                    for name in files:
                        try:
                            path = os.path.join(root, name)
                            freed_space += os.path.getsize(path)
                            os.remove(path)
                        except (OSError, PermissionError): continue
                    for name in dirs:
                        try: shutil.rmtree(os.path.join(root, name), ignore_errors=True)
                        except (OSError, PermissionError): continue
        print(f"  {Fore.GREEN}✔ Freed approximately {freed_space / 1024**2:.2f} MB of space.")

class SFCScan(Tool):
    def __init__(self):
        super().__init__("Scan System Files (SFC)", "Scans and repairs protected system files", long_running=True)

    def execute(self) -> None:
        if self.confirm_action():
            SystemUtils.run_command_streamed("sfc /scannow", self.name)

class FlushDNS(Tool):
    def __init__(self):
        super().__init__("Flush DNS Cache", "Clears the local DNS resolver cache")
    
    def execute(self) -> None:
        SystemUtils.run_command_streamed("ipconfig /flushdns", self.name)

class EnableUltimatePerformance(Tool):
    def __init__(self):
        super().__init__("Enable Ultimate Performance", "Activates the high-performance power plan")

    def execute(self) -> None:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}--- {self.name} ---")
        try:
            guid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
            subprocess.check_output(f"powercfg /duplicatescheme {guid}", shell=True, stderr=subprocess.DEVNULL)
            subprocess.check_output(f"powercfg /setactive {guid}", shell=True, stderr=subprocess.DEVNULL)
            print(f"  {Fore.GREEN}✔ Ultimate Performance power plan enabled and set as active.")
        except subprocess.CalledProcessError:
            print(f"  {Fore.RED}✖ Could not enable the power plan. It may already exist.")

class HelldiversCache(Tool):
    def __init__(self):
        super().__init__("Helldivers 2: Clear Cache", "Can resolve stuttering by deleting the shader cache")

    def execute(self) -> None:
        path = os.path.join(os.environ.get('APPDATA', ''), 'Arrowhead', 'Helldivers2', 'shader_cache')
        if os.path.exists(path) and self.confirm_action():
            with Spinner("Deleting cache..."):
                shutil.rmtree(path, ignore_errors=True)
            print(f"  {Fore.GREEN}✔ Helldivers 2 shader cache cleared.")
        else:
            print(f"  {Fore.YELLOW}i Shader cache not found or action cancelled.")

class HelldiversConfig(Tool):
    def __init__(self):
        super().__init__("Helldivers 2: Reset Config", "Resets all in-game settings to default", dangerous=True)
    
    def execute(self) -> None:
        path = os.path.join(os.environ.get('APPDATA', ''), 'Arrowhead', 'Helldivers2', 'user_settings.config')
        if os.path.exists(path) and self.confirm_action():
            with Spinner("Deleting config..."):
                try: os.unlink(path)
                except OSError: pass
            print(f"  {Fore.GREEN}✔ User config deleted. The game will create a new one on launch.")
        else:
            print(f"  {Fore.YELLOW}i User config not found or action cancelled.")

class SystemInfoTool(Tool):
    def __init__(self):
        super().__init__("System Information Report", "Displays a detailed report of your hardware")

    def execute(self) -> None:
        App.display_header()
        print(f"\n{Fore.CYAN}{Style.BRIGHT}--- {self.name} ---")
        with Spinner("Gathering system data..."): time.sleep(0.5)
        
        # ... (rest of the system info report logic is unchanged) ...
        try:
            print(f"\n{Fore.CYAN}--- System & OS ---")
            uname = platform.uname()
            print(f"  {Fore.WHITE}System: {Fore.YELLOW}{uname.system} {uname.release} ({uname.version})")
        except Exception: print(f"  {Fore.RED}Could not retrieve OS info.")

        try:
            print(f"\n{Fore.CYAN}--- CPU ---")
            print(f"  {Fore.WHITE}Processor: {Fore.YELLOW}{platform.processor()}")
            print(f"  {Fore.WHITE}Cores: {Fore.YELLOW}{psutil.cpu_count(logical=False)} Physical, {psutil.cpu_count(logical=True)} Logical")
        except Exception: print(f"  {Fore.RED}Could not retrieve CPU info.")
        
        try:
            print(f"\n{Fore.CYAN}--- Memory (RAM) ---")
            svmem = psutil.virtual_memory()
            print(f"  {Fore.WHITE}Total: {Fore.YELLOW}{svmem.total / 1024**3:.2f} GB | Used: {svmem.used / 1024**3:.2f} GB ({svmem.percent}%)")
        except Exception: print(f"  {Fore.RED}Could not retrieve RAM info.")

        try:
            if platform.system() == "Windows":
                print(f"\n{Fore.CYAN}--- Graphics (GPU) ---")
                cmd = "wmic path win32_VideoController get name"
                gpus = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip().split('\n')[1:]
                for i, gpu in enumerate(gpus):
                    if gpu.strip(): print(f"  {Fore.WHITE}GPU {i}: {Fore.YELLOW}{gpu.strip()}")
        except Exception: print(f"  {Fore.YELLOW}Could not retrieve GPU info.")
        
        print(f"\n{Style.BRIGHT}--- Report Complete! ---")
        # This tool handles its own pause, unlike others.

# --- MAIN APPLICATION CLASS ---

class App:
    """The main application class that orchestrates everything."""
    def __init__(self):
        self.main_menu = Menu("Main Menu", {
            '1': Menu("General Cleaning", {
                'a': CleanTempFiles(),
            }),
            '2': Menu("System Repair & Optimization", {
                'a': SFCScan(),
                'b': EnableUltimatePerformance(),
                'c': FlushDNS(),
            }),
            '3': Menu("Game Specific Fixes", {
                '1': Menu("Helldivers 2", {
                    'a': HelldiversCache(),
                    'b': HelldiversConfig(),
                })
            }),
            '4': SystemInfoTool(),
        })
        
    @staticmethod
    def display_header():
        """Displays the application's main header."""
        SystemUtils.clear_screen()
        print(Fore.CYAN + Style.BRIGHT + "==================================================")
        print(Fore.CYAN + Style.BRIGHT + "                     PC CARE")
        print(Fore.CYAN + Style.BRIGHT + "        (Computer Assistance & Repair Engine)")
        print(Fore.CYAN + Style.BRIGHT + "==================================================")
        print(Fore.YELLOW + "\nA modern, open-source utility for gamers and power users")
        print(Fore.YELLOW + "to clean, repair, and optimize their Windows PC.\n")
        print(Style.DIM + "=" * 50)

    def run(self):
        """Starts the main application loop."""
        if platform.system() == "Windows" and not SystemUtils.is_admin():
            print(f"{Fore.YELLOW}Requesting administrator privileges...")
            try:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            except Exception as e:
                print(f"{Fore.RED}Failed to elevate privileges: {e}. Please run as administrator.")
                input("Press Enter to exit.")
            return

        while True:
            App.display_header()
            print(f"  {Fore.CYAN}--- {self.main_menu.name} ---")
            for key, item in self.main_menu.items.items():
                print(f"  {Fore.CYAN}{key}.{Style.RESET_ALL} {Style.BRIGHT}{item.name}")
            print(f"\n  {Fore.CYAN}0.{Style.RESET_ALL} Exit")
            print(Style.DIM + "=" * 50)
            
            choice = input("Enter your choice: ")
            if choice == '0':
                break
                
            selected_item = self.main_menu.items.get(choice)
            if isinstance(selected_item, Menu):
                selected_item.display()
            elif isinstance(selected_item, Tool):
                selected_item.execute()
                input(f"\n{Style.DIM}Press Enter to return to the main menu...")
            else:
                print(f"{Fore.RED}Invalid choice.")
                time.sleep(1)

        print(f"\n{Fore.YELLOW}Exiting PC CARE. Keep your system healthy! ✨")


if __name__ == "__main__":
    app = App()
    app.run()

