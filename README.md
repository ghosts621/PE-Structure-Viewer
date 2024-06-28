# PE Structure Viewer

PE Structure Viewer is a graphical tool developed using PyQt5 to visualize and explore the Portable Executable (PE) file format structure. It allows users to navigate through various PE headers and sections, providing detailed information about each field.

## Features

- Visualize PE file structure including DOS Header, NT Headers, Section Headers, and more.
- Search functionality to find specific offsets, structure names, or values.
- Highlight search results and navigate through matches.
- Display detailed descriptions and offsets for each field.
- Load and display images next to the PE structure for better understanding.

## Screenshots

![PE Structure Viewer Screenshot](docs/screenshot.png)

*Add a descriptive screenshot here to showcase your tool's interface. Save the screenshot in the repository and update the path accordingly.*

## Installation

To run PE Structure Viewer, you need to have Python and PyQt5 installed. Follow these steps to set up the environment:

1. Clone the repository:
   ```bash
   git clone https://github.com/ghosts621/pestructureviewer.git
   cd pestructureviewer
   ```

2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python pestructureviewer.py
   ```

## Usage

1. Launch the application by running `pestructureviewer.py`.
2. Use the search bar to find specific offsets, structure names, or values within the PE file.
3. Click on any item in the tree view to see detailed information about that field.
4. Double-click on items to open corresponding header files (if available).
5. The image next to the tree view provides a visual representation of the PE structure.

## Contributing

Contributions are welcome! If you have suggestions, bug reports, or improvements, please create an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by various PE file format documentation and resources.
- Special thanks to the developers of PyQt5 and other dependencies used in this project.
