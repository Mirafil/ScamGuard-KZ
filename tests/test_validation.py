"""Reproducibility and model rule tests for the synthetic 600-case lab."""
from pathlib import Path
import csv
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from reproduce_validation import generate_dataset, evaluate_score, metrics

class TestValidation(unittest.TestCase):
    def test_dataset_is_reproducible(self):
        generated=list(generate_dataset())
        self.assertEqual(len(generated),600)
        with (ROOT/'data'/'synthetic_validation_600.csv').open(encoding='utf-8',newline='') as f:
            actual=list(csv.DictReader(f))
        self.assertEqual(len(actual),600)
        self.assertEqual(actual[0]['id'],generated[0]['id'])
        self.assertEqual([int(v['is_fraud']) for v in actual], [v['is_fraud'] for v in generated])
        self.assertEqual([int(v['amount']) for v in actual], [v['amount'] for v in generated])

    def test_metrics_at_fixed_threshold(self):
        rows=list(generate_dataset())
        self.assertEqual((metrics(rows,40)['tp'],metrics(rows,40)['fp'],metrics(rows,40)['fn'],metrics(rows,40)['tn']),
                         (88,171,40,301))

    def test_high_risk_test_case(self):
        row={'amount':150000,'usual_amount':25000,'known':0,'new_account':1,
             'odd_time':0,'multi_senders':29,'rapid_outflow':1,'risky_links':1,'is_fraud':1}
        self.assertEqual(evaluate_score(row),100)

if __name__=='__main__':
    unittest.main()
