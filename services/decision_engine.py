import logging

class DecisionEngine:
    """
    Engine to analyze reputation data and determine threat level.
    Follows the Single Responsibility Principle (SRP) by focusing only on
    analyzing reputation data and determining threat levels.
    """
    
    def __init__(self):
        """Initialize the decision engine."""
        # Thresholds for determining verdicts
        self.thresholds = {
            'safe': 0.15,        # Below this is considered safe
            'suspicious': 0.40,  # Below this is considered suspicious, above is dangerous
        }
        
        # Bootstrap color mappings for verdicts
        self.verdict_colors = {
            'SAFE': 'success',
            'SUSPICIOUS': 'warning',
            'DANGEROUS': 'danger'
        }
    
    def analyze(self, reputation_data):
        """
        Analyze reputation data and determine threat level.
        
        Args:
            reputation_data (dict): The reputation data to analyze
            
        Returns:
            dict: Analysis result containing score, verdict, color, and details
        """
        # Calculate threat score
        score = self._calculate_score(reputation_data)
        
        # Determine verdict
        verdict = self._determine_verdict(score)
        
        # Get color for verdict
        color = self._get_color_for_verdict(verdict)
        
        # Extract details
        details = self._extract_details(reputation_data)
        
        # Return analysis result
        return {
            'score': round(score, 2),
            'verdict': verdict,
            'color': color,
            'details': details
        }
    
    def _calculate_score(self, reputation_data):
        """
        Calculate threat score based on reputation data.
        
        Args:
            reputation_data (dict): The reputation data
            
        Returns:
            float: The calculated threat score
        """
        stats = reputation_data.get('stats', {})
        
        # Get counts
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        
        # Calculate total checks
        total = malicious + suspicious + harmless + undetected
        
        # Avoid division by zero
        if total == 0:
            logging.warning("No detection data in reputation results")
            return 0.0
        
        # Calculate weighted score
        # Give more weight to malicious findings
        weighted_malicious = malicious * 1.0
        weighted_suspicious = suspicious * 0.5
        
        # Calculate final score (0-1 range)
        score = (weighted_malicious + weighted_suspicious) / total
        
        return score
    
    def _determine_verdict(self, score):
        """
        Determine verdict based on threat score.
        
        Args:
            score (float): The threat score
            
        Returns:
            str: The verdict (SAFE, SUSPICIOUS, or DANGEROUS)
        """
        if score <= self.thresholds['safe']:
            return 'SAFE'
        elif score <= self.thresholds['suspicious']:
            return 'SUSPICIOUS'
        else:
            return 'DANGEROUS'
    
    def _get_color_for_verdict(self, verdict):
        """
        Get color code for a verdict.
        
        Args:
            verdict (str): The verdict
            
        Returns:
            str: Bootstrap color class
        """
        return self.verdict_colors.get(verdict, 'secondary')
    
    def _extract_details(self, reputation_data):
        """
        Extract relevant details from reputation data.
        
        Args:
            reputation_data (dict): The reputation data
            
        Returns:
            dict: Relevant details for display
        """
        meta = reputation_data.get('meta', {})
        results = reputation_data.get('results', {})
        
        # Sort engine results by category
        categorized_results = {
            'malicious': [],
            'suspicious': [],
            'harmless': [],
            'undetected': []
        }
        
        for engine_name, result in results.items():
            category = result.get('category', 'undetected')
            if category in categorized_results:
                categorized_results[category].append({
                    'engine': engine_name,
                    'result': result.get('result', ''),
                    'category': category
                })
        
        # Return structured details
        return {
            'last_analysis_date': meta.get('last_analysis_date', 0),
            'engines': categorized_results
        }