Installation Guide
==================

This guide provides detailed instructions for installing Dexray Insight and its dependencies on various platforms.

Requirements
------------

**System Requirements**:

* Python 3.8 or higher
* 2GB+ available RAM (4GB recommended for large APKs)
* 1GB+ available disk space

**Platform Support**:

* Linux (Ubuntu 18.04+, CentOS 7+)
* macOS (10.14+)
* Windows 10/11 (with WSL2 recommended)

Core Dependencies
-----------------

**Required Python Packages**:

The following packages are automatically installed with Dexray Insight:

* ``androguard`` - Core Android analysis functionality
* ``lxml`` - XML parsing for manifests
* ``requests`` - HTTP client for API communications
* ``pyyaml`` - YAML configuration file parsing
* ``colorama`` - Cross-platform colored terminal output
* ``tqdm`` - Progress bars for analysis operations

**Optional Dependencies**:

For enhanced native binary analysis:

* ``r2pipe`` - Radare2 Python bindings for native analysis

Installation Methods
--------------------

Development Installation (Recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For development and customization:

.. code-block:: bash

   # Clone the repository
   git clone https://github.com/fkie-cad/Sandroid_Dexray-Insight.git
   cd Sandroid_Dexray-Insight

   # Install in development mode
   python3 -m pip install -e .

   # Verify installation
   dexray-insight --version

This method allows you to modify the source code and see changes immediately without reinstalling.

Standard Installation
~~~~~~~~~~~~~~~~~~~~~

For production use:

.. code-block:: bash

   # Install from source
   git clone https://github.com/fkie-cad/Sandroid_Dexray-Insight.git
   cd Sandroid_Dexray-Insight
   python3 -m pip install .

   # Or install directly via PyPI
   python3 -m pip install dexray-insight
   
   # Verify installation
   dexray-insight --version   

Virtual Environment Setup (Recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using a virtual environment prevents package conflicts:

.. code-block:: bash

   # Create virtual environment
   python3 -m venv dexray-env
   
   # Activate virtual environment
   # On Linux/macOS:
   source dexray-env/bin/activate
   # On Windows:
   dexray-env\Scripts\activate

   # Install Dexray Insight
   python3 -m pip install -e .

Docker Installation
~~~~~~~~~~~~~~~~~~~

For containerized analysis:

.. code-block:: bash

   # Build Docker image
   docker build -t dexray-insight .

   # Run analysis in container
   docker run -v /path/to/apks:/app/ dexray-insight /app/yourfile.apk

External Tools Setup
--------------------

For enhanced analysis capabilities, install the following external tools:

Java Development Kit (JDK)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Required for APK processing tools:

.. code-block:: bash

   # Ubuntu/Debian
   sudo apt update
   sudo apt install openjdk-11-jdk

   # macOS with Homebrew
   brew install openjdk@11

   # Verify installation
   java -version

APKTool
~~~~~~~

For APK disassembly and resource extraction:

.. code-block:: bash

   # Download APKTool
   wget https://github.com/iBotPeaches/Apktool/releases/download/v2.8.1/apktool_2.8.1.jar
   
   # Set executable permissions and PATH
   sudo mv apktool_2.8.1.jar /usr/local/bin/apktool.jar
   echo 'alias apktool="java -jar /usr/local/bin/apktool.jar"' >> ~/.bashrc

Update your ``dexray.yaml`` configuration:

.. code-block:: yaml

   tools:
     apktool:
       enabled: true
       path: "/usr/local/bin/apktool.jar"
       timeout: 600
       java_options: ["-Xmx2g"]

JADX (Optional)
~~~~~~~~~~~~~~~

For Java decompilation:

.. code-block:: bash

   # Download JADX
   wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
   unzip jadx-1.4.7.zip -d /opt/jadx
   
   # Add to PATH
   echo 'export PATH="/opt/jadx/bin:$PATH"' >> ~/.bashrc
   source ~/.bashrc

Update your ``dexray.yaml`` configuration:

.. code-block:: yaml

   tools:
     jadx:
       enabled: true
       path: "/opt/jadx/bin/jadx"
       timeout: 900
       options: ["--no-debug-info", "--show-bad-code"]

Radare2 (Optional)
~~~~~~~~~~~~~~~~~~

For native binary analysis:

.. code-block:: bash

   # Ubuntu/Debian
   sudo apt install radare2

   # macOS with Homebrew
   brew install radare2

   # Install Python bindings
   python3 -m pip install r2pipe

Update your ``dexray.yaml`` configuration:

.. code-block:: yaml

   tools:
     radare2:
       enabled: true
       path: null  # Uses system PATH
       timeout: 120
       options: ["-2"]

Configuration
-------------

Create Configuration File
~~~~~~~~~~~~~~~~~~~~~~~~~~

Copy the default configuration template:

.. code-block:: bash

   # Copy default configuration
   cp dexray.yaml.template dexray.yaml
   
   # Edit configuration
   nano dexray.yaml

API Key Configuration
~~~~~~~~~~~~~~~~~~~~~

For signature detection services, add your API keys to ``dexray.yaml``:

.. code-block:: yaml

   modules:
     signature_detection:
       enabled: true
       providers:
         virustotal:
           enabled: true
           api_key: "YOUR_VIRUSTOTAL_API_KEY"
         koodous:
           enabled: true
           api_key: "YOUR_KOODOUS_API_KEY"
         triage:
           enabled: true
           api_key: "YOUR_TRIAGE_API_KEY"

Verification
------------

Test your installation:

.. code-block:: bash

   # Check version
   dexray-insight --version

   # Run help
   dexray-insight --help

   # Test with a sample APK
   dexray-insight sample.apk -d DEBUG

   # Test with security assessment
   dexray-insight sample.apk -s

   # Test configuration loading
   dexray-insight sample.apk -c dexray.yaml

Troubleshooting
---------------

Common Installation Issues
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Python Version Conflicts**:

.. code-block:: bash

   # Check Python version
   python3 --version
   
   # Use specific Python version
   python3.9 -m pip install -e .

**Missing Dependencies**:

.. code-block:: bash

   # Install system dependencies (Ubuntu)
   sudo apt update
   sudo apt install python3-dev python3-pip build-essential libxml2-dev libxslt1-dev zlib1g-dev

   # Install system dependencies (macOS)
   brew install libxml2 libxslt

**Permission Errors**:

.. code-block:: bash

   # Install with user flag
   python3 -m pip install --user -e .

   # Or use virtual environment (recommended)
   python3 -m venv venv
   source venv/bin/activate
   python3 -m pip install -e .

**Import Errors**:

.. code-block:: bash

   # Check Python path
   python3 -c "import sys; print('\n'.join(sys.path))"
   
   # Reinstall in development mode
   python3 -m pip uninstall dexray-insight
   python3 -m pip install -e .

Performance Optimization
~~~~~~~~~~~~~~~~~~~~~~~~

For large APK analysis:

.. code-block:: yaml

   # In dexray.yaml
   analysis:
     parallel_execution:
       enabled: true
       max_workers: 4
     timeout:
       module_timeout: 600  # 10 minutes
       tool_timeout: 1200   # 20 minutes

   # Memory settings for external tools
   tools:
     apktool:
       java_options: ["-Xmx4g", "-Xms2g"]
     jadx:
       options: ["--threads-count", "4"]

Getting Help
------------

If you encounter issues:

1. Check the troubleshooting section above
2. Review the logs with ``-d DEBUG`` flag
3. Consult the `GitHub Issues <https://github.com/fkie-cad/Sandroid_Dexray-Insight/issues>`_
4. Create a new issue with:
   - Your Python version (``python3 --version``)
   - Your operating system
   - Full error message
   - Steps to reproduce