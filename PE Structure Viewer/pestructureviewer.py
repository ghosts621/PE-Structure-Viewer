import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem, QTextEdit, QVBoxLayout, \
    QHBoxLayout, QWidget, QLineEdit, QPushButton, QMessageBox, QComboBox, QLabel
from PyQt5.QtGui import QPixmap, QColor, QIcon
from PyQt5.QtCore import Qt


class PEViewer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PE Structure Viewer")
        self.setGeometry(100, 100, 1800, 800)

        self.setWindowIcon(QIcon('Icon.png'))

        self.search_index = -1
        self.search_results = []

        self.centralWidget = QWidget()
        self.setCentralWidget(self.centralWidget)

        self.layout = QHBoxLayout(self.centralWidget)

        # Left layout for the tree and details
        self.left_layout = QVBoxLayout()
        self.layout.addLayout(self.left_layout)

        # Right layout for the image
        self.right_layout = QVBoxLayout()
        self.layout.addLayout(self.right_layout)

        # Add search type dropdown
        self.search_type = QComboBox()
        self.search_type.addItems(["Offset", "Structure Name", "Structure Value"])
        self.left_layout.addWidget(self.search_type)

        # Add search bar and buttons
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search...")
        self.left_layout.addWidget(self.search_bar)

        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.search_tree)
        self.left_layout.addWidget(self.search_button)

        self.next_button = QPushButton("Next Match")
        self.next_button.clicked.connect(self.find_next_match)
        self.left_layout.addWidget(self.next_button)

        self.reset_button = QPushButton("Reset Search")
        self.reset_button.clicked.connect(self.reset_search)
        self.left_layout.addWidget(self.reset_button)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["PE Structure"])
        self.tree.itemClicked.connect(self.on_item_clicked)
        self.tree.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.left_layout.addWidget(self.tree)

        self.details = QTextEdit()
        self.left_layout.addWidget(self.details)

        self.populate_tree()

        # Add the image to the right layout
        self.image_label = QLabel()
        self.image_path = 'Portable_Executable_32_bit_Structure.png'
        pixmap = QPixmap(self.image_path)
        scaled_pixmap = pixmap.scaled(1000, 1200,aspectRatioMode=Qt.KeepAspectRatio)
        self.image_label.setPixmap(scaled_pixmap)
        self.right_layout.addWidget(self.image_label)

        self.struct_to_header = {
            "IMAGE_DOS_HEADER": "winnt.h",
            "IMAGE_NT_HEADERS": "winnt.h",
            "IMAGE_FILE_HEADER": "winnt.h",
            "IMAGE_OPTIONAL_HEADER": "winnt.h",
            "IMAGE_DATA_DIRECTORY": "winnt.h",
            "IMAGE_EXPORT_DIRECTORY": "winnt.h",
            "IMAGE_IMPORT_DESCRIPTOR": "winnt.h",
            "IMAGE_RESOURCE_DIRECTORY": "winnt.h",
            "IMAGE_RUNTIME_FUNCTION_ENTRY": "winnt.h",
            "WIN_CERTIFICATE": "winnt.h",
            "IMAGE_BASE_RELOCATION": "winnt.h",
            "IMAGE_DEBUG_DIRECTORY": "winnt.h",
            "IMAGE_ARCHITECTURE_HEADER": "winnt.h",
            "IMAGE_GLOBAL_POINTER": "winnt.h",
            "IMAGE_TLS_DIRECTORY": "winnt.h",
            "IMAGE_LOAD_CONFIG_DIRECTORY": "winnt.h",
            "IMAGE_BOUND_IMPORT_DESCRIPTOR": "winnt.h",
            "IMAGE_THUNK_DATA": "winnt.h",
            "IMAGE_DELAYLOAD_DESCRIPTOR": "winnt.h",
            "IMAGE_COR20_HEADER": "winnt.h",
        }

    def search_tree(self):
        search_text = self.search_bar.text().strip()
        search_type = self.search_type.currentText()
        if search_text:
            if search_type == "Offset" and search_text.startswith("0x"):
                search_text = search_text[2:]
            self.reset_colors(self.tree.invisibleRootItem())
            self.search_results = []
            self.search_index = -1
            self.find_items(self.tree.invisibleRootItem(), search_text, search_type)
            self.find_next_match()

    def reset_colors(self, parent):
        for i in range(parent.childCount()):
            item = parent.child(i)
            item.setForeground(0, QColor(0, 0, 0))
            self.reset_colors(item)

    def find_items(self, parent, text, search_type):
        for i in range(parent.childCount()):
            item = parent.child(i)
            offset = item.data(1, 0)
            description = item.data(2, 0)

            if search_type == "Offset" and offset and text.lower() in str(offset).lower():
                self.search_results.append(item)
            elif search_type == "Structure Name" and description and text.lower() in str(description).lower():
                self.search_results.append(item)
            elif search_type == "Structure Value" and text.lower() in item.text(0).lower():
                self.search_results.append(item)
            self.find_items(item, text, search_type)

    def find_next_match(self):
        if not self.search_results:
            QMessageBox.information(self, "Search", "No matches found.")
            return

        self.search_index += 1
        if self.search_index >= len(self.search_results):
            self.search_index = 0

        item = self.search_results[self.search_index]
        self.tree.expandItem(item)
        self.tree.setCurrentItem(item)
        self.tree.scrollToItem(item)
        item.setForeground(0, QColor(255, 0, 0))

    def add_field(self, parent, name, offset, description):
        field_item = QTreeWidgetItem([name])
        parent.addChild(field_item)
        field_item.setData(1, 0, offset)
        field_item.setData(2, 0, description)
        # Set color for the field name
        field_item.setForeground(0, QColor(0, 128, 0))  # Green for field name
        field_item.setForeground(1, QColor(0, 0, 255))  # Blue for offset
        field_item.setForeground(2, QColor(128, 0, 0))  # Red for description

    def on_item_clicked(self, item, column):
        self.details.clear()
        self.details.setTextColor(QColor(0, 0, 128))  # Dark blue for text
        self.details.append(f"Field: {item.text(0)}\n")
        self.details.setTextColor(QColor(0, 128, 0))  # Green for text
        self.details.append(f"Offset and Size: {item.data(1, 0)}\n")
        self.details.setTextColor(QColor(128, 0, 0))  # Red for text
        self.details.append(f"Description: {item.data(2, 0)}\n")

    def on_item_double_clicked(self, item, column):
        struct_name = item.text(0)
        header_file = self.struct_to_header.get(struct_name)
        if header_file:
            file_path = os.path.join(r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.18362.0\um", header_file)
            if os.path.exists(file_path):
                os.startfile(file_path)
            else:
                QMessageBox.warning(self, "File Not Found", f"Header file for {struct_name} not found at {file_path}.")
        else:
            QMessageBox.warning(self, "Unknown Structure", f"No header file mapping found for {struct_name}.")

    def reset_search(self):
        self.reset_colors(self.tree.invisibleRootItem())
        self.search_results = []
        self.search_index = -1
        self.details.clear()

    def populate_tree(self):
        # Adding IMAGE_DOS_HEADER
        dos_header_item = QTreeWidgetItem(["IMAGE_DOS_HEADER"])
        self.tree.addTopLevelItem(dos_header_item)

        # Set general information directly on the IMAGE_DOS_HEADER item
        dos_header_item.setData(1, 0, "None")  # Offset and Size
        dos_header_item.setData(2, 0,
                                "The IMAGE_DOS_HEADER structure contains the DOS header, which is the initial part of the PE file. It includes important information needed for the executable to run in DOS mode and to locate the PE header.")  # Description

        self.add_field(dos_header_item, "e_magic", "Offset: 0x00, Size: 2 bytes",
                       "Magic number identifying the file as an executable, typically 'MZ'.")
        self.add_field(dos_header_item, "e_cblp", "Offset: 0x02, Size: 2 bytes", "Bytes on last page of file.")
        self.add_field(dos_header_item, "e_cp", "Offset: 0x04, Size: 2 bytes", "Pages in file.")
        self.add_field(dos_header_item, "e_crlc", "Offset: 0x06, Size: 2 bytes", "Relocations.")
        self.add_field(dos_header_item, "e_cparhdr", "Offset: 0x08, Size: 2 bytes", "Size of header in paragraphs.")
        self.add_field(dos_header_item, "e_minalloc", "Offset: 0x0A, Size: 2 bytes", "Minimum extra paragraphs needed.")
        self.add_field(dos_header_item, "e_maxalloc", "Offset: 0x0C, Size: 2 bytes", "Maximum extra paragraphs needed.")
        self.add_field(dos_header_item, "e_ss", "Offset: 0x0E, Size: 2 bytes", "Initial (relative) SS value.")
        self.add_field(dos_header_item, "e_sp", "Offset: 0x10, Size: 2 bytes", "Initial SP value.")
        self.add_field(dos_header_item, "e_csum", "Offset: 0x12, Size: 2 bytes", "Checksum.")
        self.add_field(dos_header_item, "e_ip", "Offset: 0x14, Size: 2 bytes", "Initial IP value.")
        self.add_field(dos_header_item, "e_cs", "Offset: 0x16, Size: 2 bytes", "Initial (relative) CS value.")
        self.add_field(dos_header_item, "e_lfarlc", "Offset: 0x18, Size: 2 bytes", "File address of relocation table.")
        self.add_field(dos_header_item, "e_ovno", "Offset: 0x1A, Size: 2 bytes", "Overlay number.")
        self.add_field(dos_header_item, "e_res", "Offset: 0x1C, Size: 8 bytes", "Reserved words.")
        self.add_field(dos_header_item, "e_oemid", "Offset: 0x24, Size: 2 bytes", "OEM identifier (for e_oeminfo).")
        self.add_field(dos_header_item, "e_oeminfo", "Offset: 0x26, Size: 2 bytes",
                       "OEM information; e_oemid specific.")
        self.add_field(dos_header_item, "e_res2", "Offset: 0x28, Size: 20 bytes", "Reserved words.")
        self.add_field(dos_header_item, "e_lfanew", "Offset: 0x3C, Size: 4 bytes", "File address of new exe header.")

        import_DOS_STUB = QTreeWidgetItem(["IMAGE_DOS_STUB"])
        self.tree.addTopLevelItem(import_DOS_STUB)
        # Set general information directly on the IMAGE_DOS_HEADER item
        import_DOS_STUB.setData(1, 0, "None")  # Offset and Size
        import_DOS_STUB.setData(2, 0,
                                """
                                From offset 0x40 to 0x7f is this stub program which is of 64 bytes.
                                Simple 16-bit assembly program which prints This program cannot be run in DOS mode and exit.
                                The values e_sp which is the initial stack pointer, and e_ip which is the initial instruction pointer.
                                Which will execute and print that MS-DOS text.

                                Stub code:
                                     0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68
                                     69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 
                                     74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 
                                     6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00

                                     seg000:0000                 push    cs
                                     seg000:0001                 pop     ds

                                     seg000:0002                 mov     dx, 0Eh
                                     seg000:0005                 mov     ah, 9
                                     seg000:0007                 int     21h             ; DOS - PRINT STRING
                                     seg000:0007                                         ; DS:DX -> string terminated by "$"

                                     seg000:0009                 mov     ax, 4C01h
                                     seg000:000C                 int     21h             ; DOS - 2+ - QUIT WITH EXIT CODE (EXIT)
                                     seg000:000C                                         ; AL = exit code
                                """)  # Description

        rich_header_item = QTreeWidgetItem(["Rich Header"])
        self.tree.addTopLevelItem(rich_header_item)

        rich_header_item.setData(1, 0, "None")  # Offset and Size
        rich_header_item.setData(2, 0,
                                 """
                                     Rich Header is not actually a part of the PE file format structure.
                                     Microsoft adds to any executable built using their Visual Studio toolset

                                     This chunk of data is commonly referred to as the Rich Header, it’s an undocumented structure that’s only present in executables built using the Microsoft Visual Studio toolset.
                                     This structure holds some metadata about the tools used to build the executable like their names or types and their specific versions and build numbers.

                                     Decode Rich Header:
                                     def decode_rich_header(data):
                                         import struct

                                         rich_index = data.find(b'Rich')
                                         if rich_index == -1:
                                             return None

                                         xor_key = struct.unpack_from('<I', data, rich_index + 4)[0]

                                         dans_index = data.find(b'DanS')
                                         if dans_index == -1 or dans_index >= rich_index:
                                             return None

                                         entries = []
                                         for i in range(dans_index + 8, rich_index, 8):
                                             encoded_id, encoded_count = struct.unpack_from('<II', data, i)
                                             id = encoded_id ^ xor_key
                                             count = encoded_count ^ xor_key
                                             entries.append((id, count))

                                         return entries

                                     # Example usage
                                     with open('example.exe', 'rb') as f:
                                         data = f.read()

                                     entries = decode_rich_header(data)
                                     if entries:
                                         for id, count in entries:
                                             print(f'Tool ID: {id}, Count: {count}')
                                     else:
                                         print('Rich Header not found or corrupted')

                                 """)  # Descriptio

        self.add_field(rich_header_item, "DanS Signature", "Offset: Varies, Size: 4 bytes",
                       "The 'DanS' signature (0x536E6144 in little-endian format).")

        self.add_field(rich_header_item, "Encoded Entries", "Offset: After DanS, Size: Multiple of 8 bytes",
                       "Series of encoded entries representing the tools and components used during the build process.")

        self.add_field(rich_header_item, "Rich Signature", "Offset: After the encoded entries, Size: 4 bytes",
                       "The 'Rich' signature (0x68636952 in little-endian format).")

        self.add_field(rich_header_item, "XOR Key", "Offset: After Rich signature, Size: 4 bytes",
                       "The XOR key used to encode the entries.")

        # Adding IMAGE_NT_HEADERS
        nt_headers_item = QTreeWidgetItem(["IMAGE_NT_HEADERS"])
        self.tree.addTopLevelItem(nt_headers_item)

        nt_headers_item.setData(1, 0, "None")  # Offset and Size
        nt_headers_item.setData(2, 0,
                                """
                                typedef struct _IMAGE_NT_HEADERS64 {
                                    DWORD Signature;
                                    IMAGE_FILE_HEADER FileHeader;
                                    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
                                } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

                                typedef struct _IMAGE_NT_HEADERS {
                                    DWORD Signature;
                                    IMAGE_FILE_HEADER FileHeader;
                                    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
                                } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

                                """)  # Description

        self.add_field(nt_headers_item, "Signature", "Offset: e_lfanew + 4, Size:  4 bytes",
                       "The signature of the PE file, typically (0x00004550).")

        file_header_item = QTreeWidgetItem(["IMAGE_FILE_HEADER"])
        nt_headers_item.addChild(file_header_item)

        file_header_item.setData(1, 0, "7 members")  # Offset and Size
        file_header_item.setData(2, 0,
                                 """
                                 Also called “The COFF File Header”, the File Header is a structure that holds some information about the PE file.

                                 typedef struct _IMAGE_FILE_HEADER {
                                     WORD    Machine;
                                     WORD    NumberOfSections;
                                     DWORD   TimeDateStamp;
                                     DWORD   PointerToSymbolTable;
                                     DWORD   NumberOfSymbols;
                                     WORD    SizeOfOptionalHeader;
                                     WORD    Characteristics;
                                 } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
                                 """)  # Description

        self.add_field(file_header_item, "Machine", "Offset: e_lfanew + 4, Size: 2 bytes",
                       "The machine type (e.g., IMAGE_FILE_MACHINE_I386 for x86, IMAGE_FILE_MACHINE_AMD64 for x64).")
        self.add_field(file_header_item, "NumberOfSections", "Offset: e_lfanew + 6, Size: 2 bytes",
                       "The number of sections in the file.")
        self.add_field(file_header_item, "TimeDateStamp", "Offset: e_lfanew + 8, Size: 4 bytes",
                       "The time the file was created.")
        self.add_field(file_header_item, "PointerToSymbolTable", "Offset: e_lfanew + 12, Size: 4 bytes",
                       "The file offset of the symbol table.")
        self.add_field(file_header_item, "NumberOfSymbols", "Offset: e_lfanew + 16, Size: 4 bytes",
                       "The number of symbols in the symbol table.")
        self.add_field(file_header_item, "SizeOfOptionalHeader", "Offset: e_lfanew + 20, Size: 2 bytes",
                       "The size of the optional header.")
        self.add_field(file_header_item, "Characteristics", "Offset: e_lfanew + 22, Size: 2 bytes",
                       "The characteristics of the file (e.g., executable, DLL, 32-bit).")

        optional_header_item = QTreeWidgetItem(["IMAGE_OPTIONAL_HEADER"])
        nt_headers_item.addChild(optional_header_item)

        optional_header_item.setData(1, 0, "8 members")  # Offset and Size
        optional_header_item.setData(2, 0,
                                     """
                                             The Optional Header is the most important header of the NT headers, the PE loader looks for specific information provided by that header to be able to load and run the executable.
                                             It’s called the optional header because some file types like object files don’t have it, however this header is essential for image files.


                                             typedef struct _IMAGE_OPTIONAL_HEADER {
                                                 //
                                                 // Standard fields.
                                                 //

                                                 WORD    Magic;
                                                 BYTE    MajorLinkerVersion;
                                                 BYTE    MinorLinkerVersion;
                                                 DWORD   SizeOfCode;
                                                 DWORD   SizeOfInitializedData;
                                                 DWORD   SizeOfUninitializedData;
                                                 DWORD   AddressOfEntryPoint;
                                                 DWORD   BaseOfCode;
                                                 DWORD   BaseOfData;

                                                 //
                                                 // NT additional fields.
                                                 //

                                                 DWORD   ImageBase;
                                                 DWORD   SectionAlignment;
                                                 DWORD   FileAlignment;
                                                 WORD    MajorOperatingSystemVersion;
                                                 WORD    MinorOperatingSystemVersion;
                                                 WORD    MajorImageVersion;
                                                 WORD    MinorImageVersion;
                                                 WORD    MajorSubsystemVersion;
                                                 WORD    MinorSubsystemVersion;
                                                 DWORD   Win32VersionValue;
                                                 DWORD   SizeOfImage;
                                                 DWORD   SizeOfHeaders;
                                                 DWORD   CheckSum;
                                                 WORD    Subsystem;
                                                 WORD    DllCharacteristics;
                                                 DWORD   SizeOfStackReserve;
                                                 DWORD   SizeOfStackCommit;
                                                 DWORD   SizeOfHeapReserve;
                                                 DWORD   SizeOfHeapCommit;
                                                 DWORD   LoaderFlags;
                                                 DWORD   NumberOfRvaAndSizes;
                                                 IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
                                             } IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

                                             typedef struct _IMAGE_OPTIONAL_HEADER64 {
                                                 WORD        Magic;
                                                 BYTE        MajorLinkerVersion;
                                                 BYTE        MinorLinkerVersion;
                                                 DWORD       SizeOfCode;
                                                 DWORD       SizeOfInitializedData;
                                                 DWORD       SizeOfUninitializedData;
                                                 DWORD       AddressOfEntryPoint;
                                                 DWORD       BaseOfCode;
                                                 ULONGLONG   ImageBase;
                                                 DWORD       SectionAlignment;
                                                 DWORD       FileAlignment;
                                                 WORD        MajorOperatingSystemVersion;
                                                 WORD        MinorOperatingSystemVersion;
                                                 WORD        MajorImageVersion;
                                                 WORD        MinorImageVersion;
                                                 WORD        MajorSubsystemVersion;
                                                 WORD        MinorSubsystemVersion;
                                                 DWORD       Win32VersionValue;
                                                 DWORD       SizeOfImage;
                                                 DWORD       SizeOfHeaders;
                                                 DWORD       CheckSum;
                                                 WORD        Subsystem;
                                                 WORD        DllCharacteristics;
                                                 ULONGLONG   SizeOfStackReserve;
                                                 ULONGLONG   SizeOfStackCommit;
                                                 ULONGLONG   SizeOfHeapReserve;
                                                 ULONGLONG   SizeOfHeapCommit;
                                                 DWORD       LoaderFlags;
                                                 DWORD       NumberOfRvaAndSizes;
                                                 IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
                                             } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;


                                     """)  # Description

        self.add_field(optional_header_item, "Magic", "Offset: e_lfanew + 24, Size: 2 bytes",
                       "Identifies the state of the image file.")
        self.add_field(optional_header_item, "MajorLinkerVersion", "Offset: e_lfanew + 26, Size: 1 byte",
                       "The major version number of the linker.")
        self.add_field(optional_header_item, "MinorLinkerVersion", "Offset: e_lfanew + 27, Size: 1 byte",
                       "The minor version number of the linker.")
        self.add_field(optional_header_item, "SizeOfCode", "Offset: e_lfanew + 28, Size: 4 bytes",
                       "The size of the code (text) section.")
        self.add_field(optional_header_item, "SizeOfInitializedData", "Offset: e_lfanew + 32, Size: 4 bytes",
                       "The size of the initialized data section.")
        self.add_field(optional_header_item, "SizeOfUninitializedData", "Offset: e_lfanew + 36, Size: 4 bytes",
                       "The size of the uninitialized data section (BSS).")
        self.add_field(optional_header_item, "AddressOfEntryPoint", "Offset: e_lfanew + 40, Size: 4 bytes",
                       "The address of the entry point relative to the image base when loaded into memory.")
        self.add_field(optional_header_item, "BaseOfCode", "Offset: e_lfanew + 44, Size: 4 bytes",
                       "The address that is relative to the image base of the beginning-of-code section.")
        self.add_field(optional_header_item, "BaseOfData", "Offset: e_lfanew + 48, Size: 4 bytes",
                       "The address that is relative to the image base of the beginning-of-data section.")
        self.add_field(optional_header_item, "ImageBase", "Offset: e_lfanew + 52, Size: 4 bytes",
                       "The preferred address of the first byte of the image when loaded into memory.")
        self.add_field(optional_header_item, "SectionAlignment", "Offset: e_lfanew + 56, Size: 4 bytes",
                       "The alignment (in bytes) of sections when they are loaded into memory.")
        self.add_field(optional_header_item, "FileAlignment", "Offset: e_lfanew + 60, Size: 4 bytes",
                       "The alignment factor (in bytes) that is used to align the raw data of sections in the image file.")
        self.add_field(optional_header_item, "MajorOperatingSystemVersion", "Offset: e_lfanew + 64, Size: 2 bytes",
                       "The major version number of the required operating system.")
        self.add_field(optional_header_item, "MinorOperatingSystemVersion", "Offset: e_lfanew + 66, Size: 2 bytes",
                       "The minor version number of the required operating system.")
        self.add_field(optional_header_item, "MajorImageVersion", "Offset: e_lfanew + 68, Size: 2 bytes",
                       "The major version number of the image.")
        self.add_field(optional_header_item, "MinorImageVersion", "Offset: e_lfanew + 70, Size: 2 bytes",
                       "The minor version number of the image.")
        self.add_field(optional_header_item, "MajorSubsystemVersion", "Offset: e_lfanew + 72, Size: 2 bytes",
                       "The major version number of the subsystem.")
        self.add_field(optional_header_item, "MinorSubsystemVersion", "Offset: e_lfanew + 74, Size: 2 bytes",
                       "The minor version number of the subsystem.")
        self.add_field(optional_header_item, "Win32VersionValue", "Offset: e_lfanew + 76, Size: 4 bytes",
                       "Reserved, must be zero.")
        self.add_field(optional_header_item, "SizeOfImage", "Offset: e_lfanew + 80, Size: 4 bytes",
                       "The size (in bytes) of the image, including all headers.")
        self.add_field(optional_header_item, "SizeOfHeaders", "Offset: e_lfanew + 84, Size: 4 bytes",
                       "The combined size of the following items, rounded to a multiple of the value specified in FileAlignment.")
        self.add_field(optional_header_item, "CheckSum", "Offset: e_lfanew + 88, Size: 4 bytes",
                       "The image file checksum.")
        self.add_field(optional_header_item, "Subsystem", "Offset: e_lfanew + 92, Size: 2 bytes",
                       "The subsystem that is required to run this image.")
        self.add_field(optional_header_item, "DllCharacteristics", "Offset: e_lfanew + 94, Size: 2 bytes",
                       "The DLL characteristics of the image.")
        self.add_field(optional_header_item, "SizeOfStackReserve", "Offset: e_lfanew + 96, Size: 4 bytes",
                       "The size of the stack to reserve.")
        self.add_field(optional_header_item, "SizeOfStackCommit", "Offset: e_lfanew + 100, Size: 4 bytes",
                       "The size of the stack to commit.")
        self.add_field(optional_header_item, "SizeOfHeapReserve", "Offset: e_lfanew + 104, Size: 4 bytes",
                       "The size of the local heap space to reserve.")
        self.add_field(optional_header_item, "SizeOfHeapCommit", "Offset: e_lfanew + 108, Size: 4 bytes",
                       "The size of the local heap space to commit.")
        self.add_field(optional_header_item, "LoaderFlags", "Offset: e_lfanew + 112, Size: 4 bytes",
                       "Reserved, must be zero.")
        self.add_field(optional_header_item, "NumberOfRvaAndSizes", "Offset: e_lfanew + 116, Size: 4 bytes",
                       "The number of data-directory entries in the remainder of the optional header.")
        self.add_field(optional_header_item, "DataDirectory", "Offset: e_lfanew + 120, Size: 128 bytes",
                       "An array of 16 IMAGE_DATA_DIRECTORY structures, each describing a location and size.")

        Data_Directory_item = QTreeWidgetItem(["IMAGE_DATA_DIRECTORY"])
        optional_header_item.addChild(Data_Directory_item)

        Data_Directory_item.setData(1, 0, "2 members")  # Offset and Size
        Data_Directory_item.setData(2, 0,
                                    """
                                            Data Directories contain useful information needed by the loader, an example of a very important directory is the Import Directory which contains a list of external functions imported from other libraries, we’ll discuss it in more detail when we go over PE imports.


                                            The last member of the IMAGE_OPTIONAL_HEADER structure was an array of IMAGE_DATA_DIRECTORY structures defined.
                                            #define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

                                            typedef struct _IMAGE_DATA_DIRECTORY {
                                                DWORD   VirtualAddress;
                                                DWORD   Size;
                                            } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

                                            // Directory Entries

                                            #define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
                                            #define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
                                            #define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
                                            #define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
                                            #define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
                                            #define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
                                            #define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
                                            //      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
                                            #define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
                                            #define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
                                            #define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
                                            #define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
                                            #define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
                                            #define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
                                            #define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
                                            #define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

                                    """)  # Description

        Export_Directory_item = QTreeWidgetItem(["IMAGE_EXPORT_DIRECTORY"])
        Data_Directory_item.addChild(Export_Directory_item)
        self.add_field(Export_Directory_item, "Characteristics", "Offset: 0x00, Size: 4 bytes",
                       "Reserved, must be zero")
        self.add_field(Export_Directory_item, "TimeDateStamp", "Offset: 0x04, Size: 4 bytes",
                       "The time and date that the export data was created")
        self.add_field(Export_Directory_item, "MajorVersion", "Offset: 0x08, Size: 2 bytes",
                       "Description: The major version number of the export table")
        self.add_field(Export_Directory_item, "MinorVersion", "Offset: 0x0A, Size: 2 bytes",
                       "The minor version number of the export table.")
        self.add_field(Export_Directory_item, "Name", "Offset: 0x0C, Size: 4 bytes",
                       "The RVA of the ASCII string that contains the name of the DLL.")
        self.add_field(Export_Directory_item, "Base", "Offset: 0x10, Size: 4 bytes",
                       "The starting ordinal number for exports in this image. Usually set to 1.")
        self.add_field(Export_Directory_item, "NumberOfFunctions", "Offset: 0x14, Size: 4 bytes",
                       "The number of functions that are exported by the DLL.")
        self.add_field(Export_Directory_item, "NumberOfNames", "Offset: 0x18, Size: 4 bytes",
                       "The number of entries in the AddressOfNames array. This value is less than or equal to NumberOfFunctions.")
        self.add_field(Export_Directory_item, "AddressOfFunctions", "Offset: 0x1C, Size: 4 bytes",
                       "The RVA of the array of RVAs of the exported functions.")
        self.add_field(Export_Directory_item, "AddressOfNames", "Offset: 0x20, Size: 4 bytes",
                       "The RVA of the array of RVAs of the ASCII strings that contain the names of the exported functions.")
        self.add_field(Export_Directory_item, "AddressOfNameOrdinals", "Offset: 0x24, Size: 4 bytes",
                       "The RVA of the array of 16-bit ordinals for the names in the AddressOfNames array.")

        import_descriptor_item = QTreeWidgetItem(["IMAGE_IMPORT_DESCRIPTOR"])
        Data_Directory_item.addChild(import_descriptor_item)

        # Set general information directly on the IMAGE_DOS_HEADER item
        import_descriptor_item.setData(1, 0, "None")  # Offset and Size
        import_descriptor_item.setData(2, 0,
                                       """

                                       typedef struct _IMAGE_IMPORT_DESCRIPTOR {
                                                           union {
                                                               DWORD   Characteristics;
                                                               DWORD   OriginalFirstThunk;
                                                           } DUMMYUNIONNAME;
                                                           DWORD   TimeDateStamp;
                                                           DWORD   ForwarderChain;
                                                           DWORD   Name;
                                                           DWORD   FirstThunk;
                                                       } IMAGE_IMPORT_DESCRIPTOR;
                                                       typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
                                       """)  # Description

        self.add_field(import_descriptor_item, "Characteristics/OriginalFirstThunk", "Offset: 0x00, Size: 4 bytes",
                       "RVA to original unbound IAT (PIMAGE_THUNK_DATA).")
        self.add_field(import_descriptor_item, "TimeDateStamp", "Offset: 0x04, Size: 4 bytes",
                       "0 if not bound, otherwise date/time stamp of the bound import.")
        self.add_field(import_descriptor_item, "ForwarderChain", "Offset: 0x08, Size: 4 bytes", "-1 if no forwarders.")
        self.add_field(import_descriptor_item, "Name", "Offset: 0x0C, Size: 4 bytes", "RVA to the DLL name (PBYTE).")
        self.add_field(import_descriptor_item, "FirstThunk", "Offset: 0x10, Size: 4 bytes",
                       "RVA to IAT (PIMAGE_THUNK_DATA).")

        # Adding IMAGE_RESOURCE_DIRECTORY to the tree
        resource_directory_item = QTreeWidgetItem(["IMAGE_RESOURCE_DIRECTORY"])
        Data_Directory_item.addChild(resource_directory_item)

        self.add_field(resource_directory_item, "Characteristics", "Offset: 0x00, Size: 4 bytes",
                       "Characteristics of the resource directory.")
        self.add_field(resource_directory_item, "TimeDateStamp", "Offset: 0x04, Size: 4 bytes",
                       "Time and date the resource directory was created.")
        self.add_field(resource_directory_item, "MajorVersion", "Offset: 0x08, Size: 2 bytes", "Major version number.")
        self.add_field(resource_directory_item, "MinorVersion", "Offset: 0x0A, Size: 2 bytes", "Minor version number.")
        self.add_field(resource_directory_item, "NumberOfNamedEntries", "Offset: 0x0C, Size: 2 bytes",
                       "Number of named entries in the directory.")
        self.add_field(resource_directory_item, "NumberOfIdEntries", "Offset: 0x0E, Size: 2 bytes",
                       "Number of ID entries in the directory.")

        # Adding IMAGE_RUNTIME_FUNCTION_ENTRY to the tree
        exception_table_item = QTreeWidgetItem(["IMAGE_RUNTIME_FUNCTION_ENTRY"])
        Data_Directory_item.addChild(exception_table_item)

        self.add_field(exception_table_item, "BeginAddress", "Offset: 0x00, Size: 4 bytes",
                       "The starting address of the function.")
        self.add_field(exception_table_item, "EndAddress", "Offset: 0x04, Size: 4 bytes",
                       "The ending address of the function.")
        self.add_field(exception_table_item, "UnwindInfoAddress", "Offset: 0x08, Size: 4 bytes",
                       "Address of the unwind information.")

        # Adding WIN_CERTIFICATE to the tree
        certificate_table_item = QTreeWidgetItem(["WIN_CERTIFICATE"])
        Data_Directory_item.addChild(certificate_table_item)

        self.add_field(certificate_table_item, "Length", "Offset: 0x00, Size: 4 bytes", "Length of the certificate.")
        self.add_field(certificate_table_item, "Revision", "Offset: 0x04, Size: 2 bytes",
                       "Revision level of the certificate.")
        self.add_field(certificate_table_item, "CertificateType", "Offset: 0x06, Size: 2 bytes", "Type of certificate.")
        self.add_field(certificate_table_item, "Certificate", "Offset: 0x08, Size: Variable", "The certificate data.")

        # Adding IMAGE_BASE_RELOCATION to the tree
        base_relocation_table_item = QTreeWidgetItem(["IMAGE_BASE_RELOCATION"])
        Data_Directory_item.addChild(base_relocation_table_item)

        self.add_field(base_relocation_table_item, "VirtualAddress", "Offset: 0x00, Size: 4 bytes",
                       "The virtual address of the block.")
        self.add_field(base_relocation_table_item, "SizeOfBlock", "Offset: 0x04, Size: 4 bytes",
                       "The size of the relocation block.")

        # Adding IMAGE_DEBUG_DIRECTORY to the tree
        debug_data_item = QTreeWidgetItem(["IMAGE_DEBUG_DIRECTORY"])
        Data_Directory_item.addChild(debug_data_item)

        self.add_field(debug_data_item, "Characteristics", "Offset: 0x00, Size: 4 bytes",
                       "Characteristics of the debug data.")
        self.add_field(debug_data_item, "TimeDateStamp", "Offset: 0x04, Size: 4 bytes",
                       "Time and date the debug data was created.")
        self.add_field(debug_data_item, "MajorVersion", "Offset: 0x08, Size: 2 bytes", "Major version number.")
        self.add_field(debug_data_item, "MinorVersion", "Offset: 0x0A, Size: 2 bytes", "Minor version number.")
        self.add_field(debug_data_item, "Type", "Offset: 0x0C, Size: 4 bytes", "Type of debug data.")
        self.add_field(debug_data_item, "SizeOfData", "Offset: 0x10, Size: 4 bytes", "Size of the debug data.")
        self.add_field(debug_data_item, "AddressOfRawData", "Offset: 0x14, Size: 4 bytes", "Address of the raw data.")
        self.add_field(debug_data_item, "PointerToRawData", "Offset: 0x18, Size: 4 bytes",
                       "File pointer to the raw data.")

        # Adding IMAGE_ARCHITECTURE_HEADER to the tree
        architecture_data_item = QTreeWidgetItem(["IMAGE_ARCHITECTURE_HEADER"])
        Data_Directory_item.addChild(architecture_data_item)

        self.add_field(architecture_data_item, "HeaderSize", "Offset: 0x00, Size: 4 bytes",
                       "Size of the architecture-specific header.")
        self.add_field(architecture_data_item, "FirstEntryRVA", "Offset: 0x04, Size: 4 bytes",
                       "RVA of the first entry.")

        # Adding IMAGE_GLOBAL_POINTER to the tree
        global_pointer_item = QTreeWidgetItem(["IMAGE_GLOBAL_POINTER"])
        Data_Directory_item.addChild(global_pointer_item)

        self.add_field(global_pointer_item, "Reserved", "Offset: 0x00, Size: 4 bytes", "Reserved for future use.")

        # Adding IMAGE_TLS_DIRECTORY to the tree
        tls_table_item = QTreeWidgetItem(["IMAGE_TLS_DIRECTORY"])
        Data_Directory_item.addChild(tls_table_item)

        self.add_field(tls_table_item, "StartAddressOfRawData", "Offset: 0x00, Size: 4 bytes",
                       "Start address of the raw data.")
        self.add_field(tls_table_item, "EndAddressOfRawData", "Offset: 0x04, Size: 4 bytes",
                       "End address of the raw data.")
        self.add_field(tls_table_item, "AddressOfIndex", "Offset: 0x08, Size: 4 bytes", "Address of the index.")
        self.add_field(tls_table_item, "AddressOfCallBacks", "Offset: 0x0C, Size: 4 bytes", "Address of the callbacks.")
        self.add_field(tls_table_item, "SizeOfZeroFill", "Offset: 0x10, Size: 4 bytes", "Size of zero fill.")
        self.add_field(tls_table_item, "Characteristics", "Offset: 0x14, Size: 4 bytes", "Characteristics of the TLS.")

        # Adding IMAGE_LOAD_CONFIG_DIRECTORY to the tree
        load_config_table_item = QTreeWidgetItem(["IMAGE_LOAD_CONFIG_DIRECTORY"])
        Data_Directory_item.addChild(load_config_table_item)

        self.add_field(load_config_table_item, "Size", "Offset: 0x00, Size: 4 bytes",
                       "Size of the load configuration structure.")
        self.add_field(load_config_table_item, "TimeDateStamp", "Offset: 0x04, Size: 4 bytes",
                       "Time and date the load configuration structure was created.")
        self.add_field(load_config_table_item, "MajorVersion", "Offset: 0x08, Size: 2 bytes", "Major version number.")
        self.add_field(load_config_table_item, "MinorVersion", "Offset: 0x0A, Size: 2 bytes", "Minor version number.")
        self.add_field(load_config_table_item, "GlobalFlagsClear", "Offset: 0x0C, Size: 4 bytes",
                       "Global flags to clear.")
        self.add_field(load_config_table_item, "GlobalFlagsSet", "Offset: 0x10, Size: 4 bytes", "Global flags to set.")
        self.add_field(load_config_table_item, "CriticalSectionDefaultTimeout", "Offset: 0x14, Size: 4 bytes",
                       "Default timeout for critical sections.")
        self.add_field(load_config_table_item, "DeCommitFreeBlockThreshold", "Offset: 0x18, Size: 4 bytes",
                       "Threshold for decommitting free blocks.")
        self.add_field(load_config_table_item, "DeCommitTotalFreeThreshold", "Offset: 0x1C, Size: 4 bytes",
                       "Total free threshold for decommitting.")
        # Additional fields can be added here as needed

        # Adding IMAGE_BOUND_IMPORT_DESCRIPTOR to the tree
        bound_import_table_item = QTreeWidgetItem(["IMAGE_BOUND_IMPORT_DESCRIPTOR"])
        Data_Directory_item.addChild(bound_import_table_item)

        # Set general information directly on the IMAGE_DOS_HEADER item
        bound_import_table_item.setData(1, 0, "None")  # Offset and Size
        bound_import_table_item.setData(2, 0,
                                        """
                                     typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
                                         DWORD   TimeDateStamp;
                                         WORD    OffsetModuleName;
                                         WORD    NumberOfModuleForwarderRefs;
                                     // Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
                                     } IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;
                                        """)  # Description

        self.add_field(bound_import_table_item, "TimeDateStamp", "Offset: 0x00, Size: 4 bytes",
                       "Time and date the bound import was created.")
        self.add_field(bound_import_table_item, "OffsetModuleName", "Offset: 0x04, Size: 2 bytes",
                       "Offset to the module name.")
        self.add_field(bound_import_table_item, "NumberOfModuleForwarderRefs", "Offset: 0x06, Size: 2 bytes",
                       "Number of module forwarder references.")

        # Adding IMAGE_THUNK_DATA to the tree
        import_address_table_item = QTreeWidgetItem(["IMAGE_THUNK_DATA"])
        Data_Directory_item.addChild(import_address_table_item)

        self.add_field(import_address_table_item, "ForwarderString/Function/Ordinal/AddressOfData",
                       "Offset: 0x00, Size: 4 bytes",
                       "Union representing the different ways a thunk can be represented.")

        # Adding IMAGE_DELAYLOAD_DESCRIPTOR to the tree
        delay_import_descriptor_item = QTreeWidgetItem(["IMAGE_DELAYLOAD_DESCRIPTOR"])
        Data_Directory_item.addChild(delay_import_descriptor_item)

        self.add_field(delay_import_descriptor_item, "Attributes", "Offset: 0x00, Size: 4 bytes",
                       "Attributes of the delay load.")
        self.add_field(delay_import_descriptor_item, "Name", "Offset: 0x04, Size: 4 bytes", "RVA to the DLL name.")
        self.add_field(delay_import_descriptor_item, "ModuleHandle", "Offset: 0x08, Size: 4 bytes",
                       "RVA to the module handle.")
        self.add_field(delay_import_descriptor_item, "DelayImportAddressTable", "Offset: 0x0C, Size: 4 bytes",
                       "RVA to the delay import address table.")
        self.add_field(delay_import_descriptor_item, "DelayImportNameTable", "Offset: 0x10, Size: 4 bytes",
                       "RVA to the delay import name table.")
        self.add_field(delay_import_descriptor_item, "BoundDelayImportTable", "Offset: 0x14, Size: 4 bytes",
                       "RVA to the bound delay import table.")
        self.add_field(delay_import_descriptor_item, "UnloadDelayImportTable", "Offset: 0x18, Size: 4 bytes",
                       "RVA to the unload delay import table.")
        self.add_field(delay_import_descriptor_item, "TimeDateStamp", "Offset: 0x1C, Size: 4 bytes",
                       "Time and date the delay load was created.")

        # Adding IMAGE_COR20_HEADER to the tree
        clr_runtime_header_item = QTreeWidgetItem(["IMAGE_COR20_HEADER"])
        Data_Directory_item.addChild(clr_runtime_header_item)

        self.add_field(clr_runtime_header_item, "cb", "Offset: 0x00, Size: 4 bytes", "Size of the structure.")
        self.add_field(clr_runtime_header_item, "MajorRuntimeVersion", "Offset: 0x04, Size: 2 bytes",
                       "Major version of the runtime.")
        self.add_field(clr_runtime_header_item, "MinorRuntimeVersion", "Offset: 0x06, Size: 2 bytes",
                       "Minor version of the runtime.")
        self.add_field(clr_runtime_header_item, "MetaData", "Offset: 0x08, Size: 8 bytes",
                       "Metadata of the CLR header.")
        self.add_field(clr_runtime_header_item, "Flags", "Offset: 0x10, Size: 4 bytes", "Flags of the CLR header.")
        self.add_field(clr_runtime_header_item, "EntryPointToken", "Offset: 0x14, Size: 4 bytes", "Entry point token.")
        self.add_field(clr_runtime_header_item, "Resources", "Offset: 0x18, Size: 8 bytes",
                       "Resources of the CLR header.")
        self.add_field(clr_runtime_header_item, "StrongNameSignature", "Offset: 0x20, Size: 8 bytes",
                       "Strong name signature of the CLR header.")
        self.add_field(clr_runtime_header_item, "CodeManagerTable", "Offset: 0x28, Size: 8 bytes",
                       "Code manager table of the CLR header.")
        self.add_field(clr_runtime_header_item, "VTableFixups", "Offset: 0x30, Size: 8 bytes",
                       "VTable fixups of the CLR header.")
        self.add_field(clr_runtime_header_item, "ExportAddressTableJumps", "Offset: 0x38, Size: 8 bytes",
                       "Export address table jumps of the CLR header.")
        self.add_field(clr_runtime_header_item, "ManagedNativeHeader", "Offset: 0x40, Size: 8 bytes",
                       "Managed native header of the CLR header.")

        section_headers_item = QTreeWidgetItem(["IMAGE_SECTION_HEADER"])
        self.tree.addTopLevelItem(section_headers_item)

        # Set general information directly on the IMAGE_SECTION_HEADER item
        section_headers_item.setData(1, 0, "Varies")  # Offset and Size
        section_headers_item.setData(2, 0,
                                     """
         typedef struct _IMAGE_SECTION_HEADER {
             BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
             union {
                 DWORD   PhysicalAddress;
                 DWORD   VirtualSize;
             } Misc;
             DWORD   VirtualAddress;
             DWORD   SizeOfRawData;
             DWORD   PointerToRawData;
             DWORD   PointerToRelocations;
             DWORD   PointerToLinenumbers;
             WORD    NumberOfRelocations;
             WORD    NumberOfLinenumbers;
             DWORD   Characteristics;
         } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
                                     """)  # Description

        self.add_field(section_headers_item, "Name", "Offset: Varies, Size: 8 bytes",
                       "The name of the section, a byte array of size 8.")

        self.add_field(section_headers_item, "PhysicalAddress or VirtualSize", "Offset: Varies, Size: 4 bytes",
                       "The total size of the section when loaded in memory.")

        self.add_field(section_headers_item, "VirtualAddress", "Offset: Varies, Size: 4 bytes",
                       "The address of the first byte of the section relative to the image base when loaded in memory.")

        self.add_field(section_headers_item, "SizeOfRawData", "Offset: Varies, Size: 4 bytes",
                       "The size of the section on disk, must be a multiple of IMAGE_OPTIONAL_HEADER.FileAlignment.")

        self.add_field(section_headers_item, "PointerToRawData", "Offset: Varies, Size: 4 bytes",
                       "A pointer to the first page of the section within the file.")

        self.add_field(section_headers_item, "PointerToRelocations", "Offset: Varies, Size: 4 bytes",
                       "A file pointer to the beginning of relocation entries for the section, set to 0 for executable files.")

        self.add_field(section_headers_item, "PointerToLinenumbers", "Offset: Varies, Size: 4 bytes",
                       "A file pointer to the beginning of COFF line-number entries for the section, set to 0 because COFF debugging information is deprecated.")

        self.add_field(section_headers_item, "NumberOfRelocations", "Offset: Varies, Size: 2 bytes",
                       "The number of relocation entries for the section, set to 0 for executable images.")

        self.add_field(section_headers_item, "NumberOfLinenumbers", "Offset: Varies, Size: 2 bytes",
                       "The number of COFF line-number entries for the section, set to 0 because COFF debugging information is deprecated.")

        self.add_field(section_headers_item, "Characteristics", "Offset: Varies, Size: 4 bytes",
                       "Flags that describe the characteristics of the section.")

        SECTION_item = QTreeWidgetItem(["SECTION"])
        self.tree.addTopLevelItem(SECTION_item)

        # Set general information directly on the IMAGE_SECTION_HEADER item
        SECTION_item.setData(1, 0, "Varies")  # Offset and Size
        SECTION_item.setData(2, 0,
                             """
 typedef struct _IMAGE_SECTION_HEADER {
     BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
     union {
         DWORD   PhysicalAddress;
         DWORD   VirtualSize;
     } Misc;
     DWORD   VirtualAddress;
     DWORD   SizeOfRawData;
     DWORD   PointerToRawData;
     DWORD   PointerToRelocations;
     DWORD   PointerToLinenumbers;
     WORD    NumberOfRelocations;
     WORD    NumberOfLinenumbers;
     DWORD   Characteristics;
 } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
                             """)  # Description

        # Define common sections
        sections = [
            (".text", "Contains the executable code of the program."),
            (".data", "Contains the initialized data."),
            (".bss", "Contains uninitialized data."),
            (".rdata", "Contains read-only initialized data."),
            (".edata", "Contains the export tables."),
            (".idata", "Contains the import tables."),
            (".reloc", "Contains image relocation information."),
            (".rsrc", "Contains resources used by the program, including images, icons, or even embedded binaries."),
            (".tls", "Provides storage for every executing thread of the program.")
        ]

        for name, description in sections:
            section_item = QTreeWidgetItem([name])
            SECTION_item.addChild(section_item)
            self.add_field(section_item, "Name", f"Offset: Varies, Size: 8 bytes", f"The name of the section: {name}")
            self.add_field(section_item, "Description", f"Offset: Varies", f"{description}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    viewer = PEViewer()
    viewer.show()
    sys.exit(app.exec_())
