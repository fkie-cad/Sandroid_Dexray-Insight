#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
#
# # Copyright (C) {{ year }} Dexray Insight Contributors
# #
# # This file is part of Dexray Insight - Android APK Security Analysis Tool
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #     http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

"""
Class Signature Extraction for Library Detection.

Contains functionality to extract class signatures from DEX objects
for similarity-based library detection. Used in LibScan-style analysis.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

import logging
from typing import Any


class ClassSignatureExtractor:
    """
    Extracts class signatures for similarity analysis.

    Single Responsibility: Handle extraction of method signatures, opcodes,
    and class relationships from Android DEX files.
    """

    def __init__(self):
        """Initialize ClassSignatureExtractor with logger."""
        self.logger = logging.getLogger(__name__)

    def extract_class_signatures(self, dex_objects: list[Any]) -> dict[str, Any]:
        """
        Extract class signatures for similarity analysis.

        Args:
            dex_objects: List of DEX objects from androguard

        Returns:
            Dictionary of class signatures with methods, opcodes, and inheritance
        """
        signatures = {}

        try:
            for dex in dex_objects:
                # Get all classes from DEX
                for cls in dex.get_classes():
                    class_name = cls.get_name()

                    # Skip Android framework classes to focus on third-party libraries
                    if class_name.startswith("Landroid/") or class_name.startswith("Ljava/"):
                        continue

                    # Extract method signatures and opcodes
                    method_signatures = []
                    for method in cls.get_methods():
                        opcodes = []
                        try:
                            # Get method bytecode
                            if method.get_code():
                                for instruction in method.get_code().get_bc().get_instructions():
                                    opcodes.append(instruction.get_name())
                        except Exception:
                            pass

                        method_signatures.append(
                            {"name": method.get_name(), "descriptor": method.get_descriptor(), "opcodes": opcodes}
                        )

                    signatures[class_name] = {
                        "methods": method_signatures,
                        "superclass": cls.get_superclassname(),
                        "interfaces": cls.get_interfaces(),
                    }

        except Exception as e:
            self.logger.error(f"Error extracting class signatures: {str(e)}")

        return signatures

    def build_class_dependency_graph(self, dex_objects: list[Any]) -> dict[str, dict[str, Any]]:
        """
        Build a dependency graph of classes for structural analysis.

        Args:
            dex_objects: List of DEX objects from androguard

        Returns:
            Dictionary mapping class names to their dependency information
        """
        dependency_graph = {}

        try:
            for dex in dex_objects:
                for cls in dex.get_classes():
                    class_name = cls.get_name()

                    # Skip framework classes
                    if class_name.startswith("Landroid/") or class_name.startswith("Ljava/"):
                        continue

                    dependencies = set()
                    method_count = 0
                    field_count = 0

                    # Analyze methods
                    for method in cls.get_methods():
                        method_count += 1
                        try:
                            if method.get_code():
                                for instruction in method.get_code().get_bc().get_instructions():
                                    # Extract class dependencies from method calls
                                    if hasattr(instruction, "get_operands"):
                                        for operand in instruction.get_operands():
                                            if hasattr(operand, "get_name"):
                                                dep_class = operand.get_name()
                                                if (
                                                    dep_class
                                                    and not dep_class.startswith("Landroid/")
                                                    and not dep_class.startswith("Ljava/")
                                                ):
                                                    dependencies.add(dep_class)
                        except Exception:
                            pass

                    # Analyze fields
                    for field in cls.get_fields():
                        field_count += 1

                    dependency_graph[class_name] = {
                        "dependencies": list(dependencies),
                        "methods": method_count,
                        "fields": field_count,
                        "superclass": cls.get_superclassname(),
                        "interfaces": cls.get_interfaces(),
                    }

        except Exception as e:
            self.logger.error(f"Error building dependency graph: {str(e)}")

        return dependency_graph

    def extract_method_opcode_patterns(self, dex_objects: list[Any]) -> dict[str, list[str]]:
        """
        Extract method-level opcode patterns for similarity matching.

        Args:
            dex_objects: List of DEX objects from androguard

        Returns:
            Dictionary mapping method signatures to their opcode patterns
        """
        method_patterns = {}

        try:
            for dex in dex_objects:
                for cls in dex.get_classes():
                    if cls.get_name().startswith("Landroid/") or cls.get_name().startswith("Ljava/"):
                        continue

                    for method in cls.get_methods():
                        method_key = f"{cls.get_name()}.{method.get_name()}"
                        opcodes = []

                        try:
                            if method.get_code():
                                for instruction in method.get_code().get_bc().get_instructions():
                                    opcodes.append(instruction.get_name())

                                # Only store if method has meaningful opcodes
                                if len(opcodes) > 3:  # Filter out trivial methods
                                    method_patterns[method_key] = opcodes
                        except Exception:
                            pass

        except Exception as e:
            self.logger.error(f"Error extracting method patterns: {str(e)}")

        return method_patterns

    def extract_call_chain_patterns(self, dex_objects: list[Any]) -> dict[str, list[str]]:
        """
        Extract call chain patterns for advanced similarity analysis.

        Args:
            dex_objects: List of DEX objects from androguard

        Returns:
            Dictionary mapping method signatures to their call chain patterns
        """
        call_chains = {}

        try:
            for dex in dex_objects:
                for cls in dex.get_classes():
                    if cls.get_name().startswith("Landroid/") or cls.get_name().startswith("Ljava/"):
                        continue

                    for method in cls.get_methods():
                        method_key = f"{cls.get_name()}.{method.get_name()}"
                        chains = []

                        try:
                            if method.get_code():
                                for instruction in method.get_code().get_bc().get_instructions():
                                    # Look for method invocations
                                    if "invoke" in instruction.get_name():
                                        if hasattr(instruction, "get_operands"):
                                            for operand in instruction.get_operands():
                                                if hasattr(operand, "get_name"):
                                                    target_method = operand.get_name()
                                                    if (
                                                        target_method
                                                        and not target_method.startswith("Landroid/")
                                                        and not target_method.startswith("Ljava/")
                                                    ):
                                                        chains.append(target_method)

                                if chains:
                                    call_chains[method_key] = chains
                        except Exception:
                            pass

        except Exception as e:
            self.logger.error(f"Error extracting call chains: {str(e)}")

        return call_chains
