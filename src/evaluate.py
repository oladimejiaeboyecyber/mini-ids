import pandas as pd
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
import seaborn as sns
import matplotlib.pyplot as plt

def evaluate(df):
    print("\n--- Evaluating IDS Performance ---")

    # Step 1 - Known attacker IPs from our analysis
    known_attackers = [
        '192.168.0.1',
        '192.168.0.2',
        '213.155.151.149',
        '213.155.151.155'
    ]

    # Step 2 - Create ground truth labels
    # 1 = attack, 0 = normal
    df['ground_truth'] = df['src_ip'].apply(
        lambda ip: 1 if ip in known_attackers else 0
    )

    # Step 3 - Create predicted labels
    # Flag any IP that appeared in our alerts
    flagged_ips = [
        '192.168.0.1',
        '192.168.0.2',
        '213.155.151.149',
        '213.155.151.155',
        '80.239.174.116',
        '80.239.174.85',
        '80.239.174.89',
        '80.239.174.90'
    ]

    df['predicted'] = df['src_ip'].apply(
        lambda ip: 1 if ip in flagged_ips else 0
    )

    # Step 4 - Calculate metrics
    precision = precision_score(df['ground_truth'], df['predicted'])
    recall = recall_score(df['ground_truth'], df['predicted'])
    f1 = f1_score(df['ground_truth'], df['predicted'])

    print(f"Precision: {precision:.2f}")
    print(f"Recall:    {recall:.2f}")
    print(f"F1 Score:  {f1:.2f}")

    # Step 5 - Confusion matrix
    cm = confusion_matrix(df['ground_truth'], df['predicted'])
    print(f"\nConfusion Matrix:")
    print(f"True Negatives:  {cm[0][0]}")
    print(f"False Positives: {cm[0][1]}")
    print(f"False Negatives: {cm[1][0]}")
    print(f"True Positives:  {cm[1][1]}")

    # Step 6 - Visualize confusion matrix
    plt.figure(figsize=(6,4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Normal', 'Attack'],
                yticklabels=['Normal', 'Attack'])
    plt.title('IDS Confusion Matrix')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.tight_layout()
    plt.savefig('outputs/confusion_matrix.png')
    print("\nConfusion matrix saved to outputs/confusion_matrix.png")

    return precision, recall, f1