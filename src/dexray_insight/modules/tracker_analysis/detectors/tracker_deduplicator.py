#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tracker Deduplicator for Tracker Analysis

Specialized deduplicator for removing duplicate tracker detections.
Handles conflict resolution based on confidence scores and version information.

Phase 7 TDD Refactoring: Extracted from monolithic tracker_analysis.py
"""

import logging
from typing import List, Dict
from ..models import DetectedTracker


class TrackerDeduplicator:
    """
    Specialized deduplicator for tracker detection results.
    
    Single Responsibility: Remove duplicate trackers and resolve conflicts
    based on confidence scores, version information, and detection methods.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def deduplicate_trackers(self, trackers: List[DetectedTracker]) -> List[DetectedTracker]:
        """
        Remove duplicate trackers based on name, keeping the best detection.
        
        Args:
            trackers: List of detected trackers that may contain duplicates
            
        Returns:
            Deduplicated list of trackers
        """
        if not trackers:
            return []
        
        unique_trackers = {}
        
        for tracker in trackers:
            existing = unique_trackers.get(tracker.name)
            
            if not existing:
                # First detection of this tracker
                unique_trackers[tracker.name] = tracker
                self.logger.debug(f"Added new tracker: {tracker.name}")
            else:
                # Handle duplicate detection
                merged_tracker = self._resolve_duplicate(existing, tracker)
                unique_trackers[tracker.name] = merged_tracker
                self.logger.debug(f"Resolved duplicate for tracker: {tracker.name}")
        
        result = list(unique_trackers.values())
        self.logger.info(f"Deduplication: {len(trackers)} -> {len(result)} trackers")
        return result
    
    def _resolve_duplicate(self, existing: DetectedTracker, new: DetectedTracker) -> DetectedTracker:
        """
        Resolve duplicate tracker detection by merging information.
        
        Args:
            existing: Previously detected tracker
            new: Newly detected tracker
            
        Returns:
            Merged tracker with best information from both
        """
        # Determine which tracker to use as base
        if new.confidence > existing.confidence:
            primary = new
            secondary = existing
            self.logger.debug(f"Using new detection (confidence {new.confidence} > {existing.confidence})")
        elif new.confidence < existing.confidence:
            primary = existing
            secondary = new
            self.logger.debug(f"Keeping existing detection (confidence {existing.confidence} > {new.confidence})")
        else:
            # Same confidence, prefer the one with version information
            if new.version and not existing.version:
                primary = new
                secondary = existing
                self.logger.debug("Using new detection (has version info)")
            elif existing.version and not new.version:
                primary = existing
                secondary = new
                self.logger.debug("Keeping existing detection (has version info)")
            else:
                # Same confidence and version status, prefer built-in database detections
                if existing.detection_method == 'Built-in Database':
                    primary = existing
                    secondary = new
                else:
                    primary = new
                    secondary = existing
        
        # Merge information
        merged_tracker = DetectedTracker(
            name=primary.name,
            version=primary.version or secondary.version,  # Prefer any version info
            description=primary.description or secondary.description,
            category=primary.category if primary.category != 'Unknown' else secondary.category,
            website=primary.website or secondary.website,
            code_signature=primary.code_signature or secondary.code_signature,
            network_signature=primary.network_signature or secondary.network_signature,
            detection_method=primary.detection_method,
            locations=self._merge_locations(primary.locations, secondary.locations),
            confidence=max(primary.confidence, secondary.confidence)
        )
        
        return merged_tracker
    
    def _merge_locations(self, locations1: List[str], locations2: List[str]) -> List[str]:
        """
        Merge location lists, removing duplicates and limiting size.
        
        Args:
            locations1: First list of locations
            locations2: Second list of locations
            
        Returns:
            Merged and deduplicated list of locations (max 10 items)
        """
        if not locations1:
            locations1 = []
        if not locations2:
            locations2 = []
        
        # Combine and deduplicate
        combined = list(set(locations1 + locations2))
        
        # Limit to 10 locations to prevent excessive output
        return combined[:10]
    
    def group_by_category(self, trackers: List[DetectedTracker]) -> Dict[str, List[DetectedTracker]]:
        """
        Group trackers by category for organized output.
        
        Args:
            trackers: List of detected trackers
            
        Returns:
            Dictionary mapping categories to lists of trackers
        """
        categories = {}
        
        for tracker in trackers:
            category = tracker.category or 'Unknown'
            if category not in categories:
                categories[category] = []
            categories[category].append(tracker)
        
        # Sort trackers within each category by name
        for category in categories:
            categories[category].sort(key=lambda t: t.name)
        
        return categories
    
    def filter_by_confidence(self, trackers: List[DetectedTracker], 
                           min_confidence: float = 0.5) -> List[DetectedTracker]:
        """
        Filter trackers by minimum confidence threshold.
        
        Args:
            trackers: List of detected trackers
            min_confidence: Minimum confidence threshold (0.0 - 1.0)
            
        Returns:
            Filtered list of trackers meeting confidence threshold
        """
        filtered = [t for t in trackers if t.confidence >= min_confidence]
        
        if len(filtered) < len(trackers):
            removed_count = len(trackers) - len(filtered)
            self.logger.info(f"Filtered out {removed_count} trackers below confidence threshold {min_confidence}")
        
        return filtered
    
    def get_detection_stats(self, trackers: List[DetectedTracker]) -> Dict[str, int]:
        """
        Get statistics about tracker detections.
        
        Args:
            trackers: List of detected trackers
            
        Returns:
            Dictionary with detection statistics
        """
        stats = {
            'total_trackers': len(trackers),
            'with_version': len([t for t in trackers if t.version]),
            'high_confidence': len([t for t in trackers if t.confidence >= 0.9]),
            'medium_confidence': len([t for t in trackers if 0.7 <= t.confidence < 0.9]),
            'low_confidence': len([t for t in trackers if t.confidence < 0.7])
        }
        
        # Category breakdown
        categories = {}
        for tracker in trackers:
            category = tracker.category or 'Unknown'
            categories[category] = categories.get(category, 0) + 1
        
        stats['by_category'] = categories
        
        return stats