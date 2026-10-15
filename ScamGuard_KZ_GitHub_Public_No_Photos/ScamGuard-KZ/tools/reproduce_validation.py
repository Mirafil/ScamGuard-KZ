"""Reproduce ScamGuard v6 browser synthetic validation dataset and rule metrics.

This is NOT independent real-world validation. Labels generated via synthetic
randomized process using the same observable factors. Standard library only.

Run from repository root:
    python tools/reproduce_validation.py
"""
import csv
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / 'data' / 'synthetic_validation_600.csv'
RESULTS_PATH = ROOT / 'results' / 'synthetic_metrics_threshold40.json'
MODEL_VERSION = 'rules-mvp-1.0'
FIELDS = ['id','amount','usual_amount','known','new_account','odd_time','multi_senders','rapid_outflow','risky_links','is_fraud']

class JSRandom:
    """The same seeded 32-bit linear congruential generator as browser lab."""
    def __init__(self, seed=20261008):
        self.seed = seed
    def __call__(self):
        self.seed = (1664525 * self.seed + 1013904223) & 0xffffffff
        return self.seed / 4294967296


def js_round_nonnegative(value):
    return math.floor(value + 0.5)


def generate_dataset(n=600):
    rng = JSRandom()
    for i in range(n):
        risky = rng() < 0.28
        known = rng() < (0.22 if risky else 0.79)
        usual = js_round_nonnegative(8000 + rng() * 65000)
        new_account = rng() < (0.70 if risky else 0.19)
        senders = math.floor(rng() * (35 if risky else 18)) + 1
        rapid = rng() < (0.63 if risky else 0.10)
        links = rng() < (0.48 if risky else 0.06)
        odd = rng() < (0.50 if risky else 0.18)
        amount = js_round_nonnegative(usual * (0.25 + rng() * (8.2 if risky else 4.4)) / 100) * 100
        propensity = (-3.0 + (1.15 if links else 0) + (1.05 if rapid else 0)
                      + (0.75 if senders >= 10 else 0) + (0.50 if new_account else 0)
                      + (0.42 if not known else 0) + (0.55 if amount > usual * 4 else 0)
                      + (0.16 if odd else 0))
        probability = 1 / (1 + math.exp(-propensity))
        truth = int(rng() < probability)
        yield dict(id=f'SYN-{i+1:04d}', amount=amount, usual_amount=usual,
                   known=int(known), new_account=int(new_account), odd_time=int(odd),
                   multi_senders=senders, rapid_outflow=int(rapid), risky_links=int(links),
                   is_fraud=truth)


def evaluate_score(row, baseline=False):
    a = int(row['amount'])
    usual = int(row['usual_amount'])
    rules = [
        (not bool(int(row['known'])), 14),
        (a >= usual * 2, 16),
        (a >= usual * 5, 9),
        (bool(int(row['new_account'])), 10),
        (bool(int(row['odd_time'])), 9),
        (not baseline and int(row['multi_senders']) >= 10, 18),
        (not baseline and bool(int(row['rapid_outflow'])), 16),
        (not baseline and bool(int(row['risky_links'])), 17),
    ]
    return min(100, sum(points for applies, points in rules if applies))


def metrics(rows, threshold=40, baseline=False):
    tp=tn=fp=fn=0
    for row in rows:
        truth=int(row['is_fraud'])
        positive=evaluate_score(row, baseline)>=threshold
        if truth and positive: tp+=1
        elif truth and not positive: fn+=1
        elif not truth and positive: fp+=1
        else: tn+=1
    prec=tp/(tp+fp) if tp+fp else 0
    recall=tp/(tp+fn) if tp+fn else 0
    fpr=fp/(fp+tn) if fp+tn else 0
    acc=(tp+tn)/len(rows)
    f1=2*prec*recall/(prec+recall) if prec+recall else 0
    return dict(n=len(rows),tp=tp,fp=fp,fn=fn,tn=tn,
                recall=round(recall,6),false_positive_rate=round(fpr,6),
                precision=round(prec,6),f1=round(f1,6),accuracy=round(acc,6))


def main():
    rows=list(generate_dataset())
    DATA_PATH.parent.mkdir(exist_ok=True)
    with DATA_PATH.open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=FIELDS)
        writer.writeheader();writer.writerows(rows)
    threshold=40
    report=dict(model_version=MODEL_VERSION,dataset='synthetic_validation_600.csv',
        dataset_origin='Deterministic synthetic lab, seed=20261008, not real bank data',
        independent_external_validation=False, threshold=threshold,
        warning='Synthetic only. Not real fraud detection efficacy, baseline is illustrative.',
        scamguard=metrics(rows,threshold), illustrative_baseline=metrics(rows,threshold,True))
    RESULTS_PATH.parent.mkdir(exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('DATA:',DATA_PATH)
    print('METRICS:',RESULTS_PATH)
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__ == '__main__':
    main()
