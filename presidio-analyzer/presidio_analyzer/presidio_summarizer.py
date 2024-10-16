class PresidioSummarizer:
    """
    A class to summarize PII results from Microsoft Presidio.
    This class provides methods to merge overlapping entities,
    consolidate consecutive entities, and summarize PII results
    from analysis of text.
    """
    def __init__(self):
        pass

    @staticmethod
    def merge_entities(predictions:list) -> list:
        """
        Merges overlapping PII entities from predictions.
        """
        flattened_predictions = []
        for entity in predictions: 
            flattened_predictions.append({
                'word': entity['word'],
                'start': entity['start'],
                'end': entity['end'],
                'type': entity['entity_type'], 
                'score': entity['score'],
                'explanation': entity['analysis_explanation'].textual_explanation
            })
        
        flattened_predictions.sort(key=lambda x: (x['start'], -x['score']))

        merged_entities = []
        current_word = None
        current_start = None
        current_end = None
        current_type = None
        current_score = 0.0
        current_explanation = set()

        for entity in flattened_predictions:
            if current_word is None:
                current_word = entity['word']
                current_start = entity['start']
                current_end = entity['end']
                current_type = entity['type']
                current_score = entity['score']
                current_explanation = {entity['explanation']}
            else:
                if entity['start'] < current_end:
                    if entity['score'] > current_score:
                        current_word += f' {entity["word"]}'
                        current_end = entity['end']
                        current_type = entity['type']
                        current_score = entity['score']
                    current_explanation.add(entity['explanation'])
                else:
                    explanation_text = ' and '.join(sorted(current_explanation))
                    merged_entities.append({  
                        'word': current_word,
                        'start': current_start,
                        'end': current_end,
                        'type': current_type,
                        'score': current_score,
                        'explanation': explanation_text
                    })
                    current_word = entity['word']
                    current_start = entity['start']
                    current_end = entity['end']
                    current_type = entity['type']
                    current_score = entity['score']
                    current_explanation = {entity['explanation']}
        
        if current_word is not None:
            explanation_text = ' and '.join(sorted(current_explanation))
            merged_entities.append({
                'word': current_word,
                'start': current_start,
                'end': current_end,
                'type': current_type,
                'score': current_score,
                'explanation': explanation_text
            })

        return merged_entities

    @staticmethod
    def merge_consecutive_entities(entities:list) -> list:
        """
        Merges consecutive entities of the same type.
        """
        if not entities:
            return []
        merged_entities = []
        current_entity = entities[0].copy()
        for i in range(1, len(entities)):
            entity = entities[i]
            if (entity['type'] == current_entity['type'] and entity['start'] == current_entity['end']):
                current_entity['word'] += f"{entity['word']}"
                current_entity['end'] = entity['end']  
                current_entity['score'] = (current_entity['score'] + entity['score']) / 2
                current_explanation_set = set(current_entity['explanation'].split(' and '))
                new_explanation_set = set(entity['explanation'].split(' and '))
                current_entity['explanation'] = ' and '.join(sorted(current_explanation_set.union(new_explanation_set)))
            else:
                merged_entities.append(current_entity)
                current_entity = entity.copy()
        merged_entities.append(current_entity)
        return merged_entities

    def summarize_pii(self, presidio_results: list, text: str) -> list:
        """
        Summarizes PII RecognizerResult from analyzer Presidio
        """
        word_predictions = []
        for result in presidio_results:
            word = text[result.start:result.end].strip()
            word_predictions.append({
                'word': word,
                'start': result.start,
                'end': result.end,
                'entity_type': result.entity_type,
                'score': result.score,
                'analysis_explanation': result.analysis_explanation
            })
        
        merged_entities = self.merge_entities(word_predictions)
        final_entities = self.merge_consecutive_entities(merged_entities)
        return final_entities


def summarize_pii_batch(presidio_results:list) -> list:
    """
    Summarizes DictAnalyzerResult from batch analyzer Presidio.
    """

    output = []

    for item in presidio_results:
        key = item.key
        value_list = item.value
        recognizer_results = item.recognizer_results
        
        pii_scores = {}
        pii_explanations = {}

        for results in recognizer_results: 
            for result in results:
                pii_type = result.entity_type
                score = result.score  
                pii_explanation = result.analysis_explanation.textual_explanation
                
                if pii_type in pii_scores:
                    pii_scores[pii_type]['total_score'] += score
                    pii_scores[pii_type]['count'] += 1
                else:
                    pii_scores[pii_type] = {'total_score': score, 'count': 1}
                
                if pii_type in pii_explanations:
                    pii_explanations[pii_type].add(pii_explanation)
                else:
                    pii_explanations[pii_type] = {pii_explanation}


        pii_avg_scores = {pii_type: scores['total_score'] / scores['count'] 
                          for pii_type, scores in pii_scores.items()}

        pii_combined_explanations = {pii_type: ' and '.join(explanations) 
                                     for pii_type, explanations in pii_explanations.items()}

        output.append({
            'column': key,
            'n': len(value_list), 
            'avg_scores': pii_avg_scores,
            'explanation' : pii_combined_explanations
        })

    return output
