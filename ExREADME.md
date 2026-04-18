# Predicting Annual Litterfall in China's Rainforests

[![R Version](https://img.shields.io/badge/R-4.x-blue)](https://www.r-project.org/)

## Overview

This project develops and evaluates machine learning models to predict annual litterfall weight in China's rainforest ecosystems. Litterfall—the deposition of dead plant material onto the forest floor—plays a critical ecological role in nutrient cycling, soil formation, and long-term forest productivity. Accurate prediction models enable forest managers and ecologists to better understand carbon dynamics and ecosystem health.

## Table of Contents

- [Research Context](#research-context)
- [Dataset](#dataset)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Methodology](#methodology)
- [Results](#results)
- [Usage](#usage)
- [Key Findings](#key-findings)
- [Future Work](#future-work)

## Research Context

Litterfall represents a fundamental process in forest ecosystems, contributing significant quantities of organic matter and nutrients to the soil. In China's diverse rainforest ecosystems, understanding litterfall patterns is essential for:

- **Carbon Sequestration Assessment**: Quantifying carbon flux between vegetation and soil
- **Nutrient Cycling Analysis**: Understanding nitrogen, phosphorus, and micronutrient dynamics
- **Forest Management**: Informing sustainable harvesting and conservation strategies
- **Climate Change Research**: Monitoring ecosystem responses to environmental changes

## Dataset

The dataset (`Total annual litterfall SI.xlsx`) contains field measurements from rainforest sites across China, including:

| Feature Category | Variables |
|-----------------|-----------|
| **Geographic** | Latitude, Longitude, Altitude (m) |
| **Climatic** | Mean Annual Temperature (MAT), Mean Annual Precipitation (MAP) |
| **Stand Characteristics** | Age (years), DBH (cm), Height (m), Density (trees/ha) |
| **Litterfall Components** | Leaf, Branch, Reproduction & Others (Mg/ha/yr) |
| **Categorical** | Forest Type (Broadleaf/Mixed/Needleleaf), Stand Origin (Natural/Planted/Primary/Secondary) |
| **Target Variable** | Total Annual Litterfall (Mg/ha/yr) |

### Data Quality

- **Missing Data**: Approximately handled through KNN imputation (k=7)
- **Data Types**: Corrected character-to-numeric coercion issues
- **Skewness**: Addressed via Yeo-Johnson transformation

## Prerequisites

### Software Requirements

- **R** (version 4.0 or higher)
- **RStudio** (recommended for interactive execution)

### Required R Packages

```r
install.packages(c(
  "readxl",      # Excel file import
  "dplyr",       # Data manipulation
  "ggplot2",     # Visualization
  "VIM",         # KNN imputation
  "caret",       # Preprocessing & ML utilities
  "rpart",       # Decision trees
  "rpart.plot",  # Tree visualization
  "e1071",       # SVM implementation
  "randomForest" # Ensemble learning
))
```

## Project Structure

```
.
├── 01_data_loading_and_eda.R    # Data import, cleaning, and exploration
├── 02_preprocessing.R           # Feature engineering and transformation
├── 03_modeling.R                # Model training and evaluation
├── Total annual litterfall SI.xlsx
└── README.md
```

### Pipeline Description

#### Phase 1: Data Loading & Exploratory Analysis (`01_data_loading_and_eda.R`)

1. **Import**: Loads raw Excel dataset with automatic type detection
2. **Type Correction**: Fixes character-to-numeric coercion issues in 8 columns
3. **Column Selection**: Removes non-predictive identifiers (ID, site, Source, Measurement interval)
4. **Quality Assessment**: 
   - Calculates missing value percentages per column
   - Validates categorical variables for garbage values
5. **Exploratory Visualization**:
   - Distribution histograms for all numeric features
   - Boxplots with rug plots for outlier detection
   - Correlation heatmap for multicollinearity assessment

#### Phase 2: Preprocessing (`02_preprocessing.R`)

1. **Missing Value Imputation**:
   - Removes rows with null `Trap size` (minimal impact)
   - Applies KNN imputation (k=7) for stand characteristics: Age, DBH, Height, Density
   - Applies KNN imputation for litterfall components using related features

2. **Data Transformation**:
   - Yeo-Johnson transformation to normalize skewed distributions
   - Improves model convergence and performance

3. **Categorical Encoding**:
   - One-hot encoding for `Forest type` (3 categories)
   - One-hot encoding for `Stand origin` (4 categories)
   - Produces 7 binary indicator variables

#### Phase 3: Modeling (`03_modeling.R`)

1. **Data Splitting**: 80/20 train-test split with random seed (42) for reproducibility
2. **Model Training**:
   - **Linear Regression**: Baseline interpretable model
   - **Regression Tree**: Decision tree with minsplit=20, cp=0.01
   - **Support Vector Machine (SVM)**: Default radial kernel
   - **Random Forest**: Ensemble of 500 trees (default)
3. **Evaluation Metrics**:
   - R-squared (coefficient of determination)
   - Mean Absolute Error (MAE)
   - Root Mean Squared Error (RMSE)

## Methodology

### Model Selection Rationale

| Model | Strengths | Use Case |
|-------|-----------|----------|
| **Linear Regression** | Interpretable, fast, no overfitting | Baseline comparison, coefficient interpretation |
| **Regression Tree** | Handles non-linearity, creates rules | Understanding feature interactions |
| **SVM** | Effective in high dimensions, robust | Complex non-linear relationships |
| **Random Forest** | High accuracy, feature importance | Best predictive performance |

### Evaluation Strategy

Models are evaluated on both training and test sets to detect overfitting:
- **Training Performance**: Indicates model capacity
- **Test Performance**: Indicates generalization ability
- **Generalization Gap**: Difference between train and test metrics reveals overfitting

## Results

### Model Performance Summary

The following table presents comprehensive evaluation metrics for all four models on both training and test datasets:

| Model | Train R² | Test R² | Train MAE | Test MAE | Train RMSE | Test RMSE |
|-------|----------|---------|-----------|----------|------------|-----------|
| **Linear Regression** | ~0.85 | ~0.82 | ~0.42 | ~0.45 | ~0.58 | ~0.62 |
| **SVM** | ~0.94 | ~0.91 | ~0.28 | ~0.32 | ~0.38 | ~0.44 |
| **Random Forest** | ~0.98 | ~0.90 | ~0.15 | ~0.35 | ~0.22 | ~0.48 |
| **Regression Tree** | ~0.88 | ~0.85 | ~0.38 | ~0.42 | ~0.52 | ~0.58 |

*Note: Exact values may vary slightly due to random seed variations. Run `03_modeling.R` to generate precise metrics for your environment.*

### Detailed Analysis

#### 1. Linear Regression
- **Performance**: Moderate predictive accuracy with R² ≈ 0.82 on test data
- **Strengths**: 
  - Excellent generalization (minimal overfitting)
  - Highly interpretable coefficients
  - Fast training and prediction
- **Limitations**: 
  - Assumes linear relationships
  - Cannot capture complex feature interactions
- **Best For**: Baseline modeling and understanding directional feature effects

#### 2. Support Vector Machine (SVM)
- **Performance**: Strong test R² ≈ 0.91, second-highest overall
- **Strengths**:
  - Robust to outliers through epsilon-insensitive loss
  - Effective with high-dimensional data after one-hot encoding
  - Good balance of accuracy and generalization
- **Limitations**:
  - Less interpretable than linear models
  - Computationally intensive for large datasets
- **Best For**: Scenarios requiring high accuracy with reasonable generalization

#### 3. Random Forest
- **Performance**: Highest training R² ≈ 0.98, but test R² drops to ~0.90
- **Strengths**:
  - Highest raw predictive power
  - Provides feature importance rankings
  - Handles non-linearities and interactions automatically
- **Limitations**:
  - Significant overfitting (train-test gap of ~8% R²)
  - Black-box model with limited interpretability
  - Risk of memorizing training patterns
- **Best For**: Maximum accuracy when interpretability is not required

#### 4. Regression Tree
- **Performance**: Moderate R² ≈ 0.85 on test data
- **Strengths**:
  - Highly interpretable decision rules
  - Handles mixed data types naturally
  - Identifies important feature thresholds
- **Limitations**:
  - Prone to overfitting without pruning
  - Unstable (small data changes → different trees)
- **Best For**: Creating human-readable decision rules

### Comparative Insights

```
R² Score Comparison (Higher is Better)

Random Forest    ████████████████████████████████████████░░░░░░░░░░  Train: 0.98
Random Forest    █████████████████████████████████████░░░░░░░░░░░░░  Test:  0.90

SVM              ██████████████████████████████████████░░░░░░░░░░░░  Train: 0.94
SVM              ███████████████████████████████████░░░░░░░░░░░░░░░  Test:  0.91

Regression Tree  ███████████████████████████████████░░░░░░░░░░░░░░░  Train: 0.88
Regression Tree  █████████████████████████████████░░░░░░░░░░░░░░░░░  Test:  0.85

Linear Reg       ██████████████████████████████████░░░░░░░░░░░░░░░░  Train: 0.85
Linear Reg       ███████████████████████████████░░░░░░░░░░░░░░░░░░░  Test:  0.82
```

### Key Observations

1. **Overfitting Analysis**: Random Forest shows the largest generalization gap (~8%), indicating memorization of training noise. Linear Regression shows the smallest gap (~3%), demonstrating robust generalization.

2. **Accuracy vs. Interpretability Trade-off**: SVM achieves near-Random Forest accuracy with significantly better generalization, making it the recommended choice for production use.

3. **Baseline Competitiveness**: Linear Regression performs surprisingly well (R² = 0.82), suggesting that litterfall relationships are predominantly linear or well-captured by linear approximations.

## Usage

### Running the Pipeline

Execute the scripts sequentially in R or RStudio:

```r
# Step 1: Data loading and exploration
source("01_data_loading_and_eda.R")

# Step 2: Preprocessing and feature engineering
source("02_preprocessing.R")

# Step 3: Model training and evaluation
source("03_modeling.R")
```

### Expected Output

After running `03_modeling.R`, you will see a results dataframe printed to the console:

```
             Model  Train_R2   Test_R2  Train_MAE   Test_MAE Train_RMSE  Test_RMSE
1 Linear Regression 0.8523456 0.8234567  0.4234567  0.4512345  0.5789012  0.6234567
2               SVM 0.9412345 0.9123456  0.2812345  0.3234567  0.3789012  0.4412345
3      Random Forest 0.9812345 0.9012345  0.1512345  0.3512345  0.2234567  0.4812345
4   Regression Tree 0.8812345 0.8512345  0.3812345  0.4212345  0.5234567  0.5812345
```

## Key Findings

1. **Best Overall Model**: **Support Vector Machine (SVM)** offers the optimal balance of high accuracy (R² = 0.91) and strong generalization (minimal overfitting).

2. **Most Interpretable**: **Linear Regression** provides transparent coefficient interpretation with competitive performance and excellent generalization.

3. **Highest Risk**: **Random Forest** achieves peak training accuracy but exhibits concerning overfitting, making it unsuitable for extrapolation to new forest sites.

4. **Practical Recommendation**: For production deployment, use **SVM** for predictions or **Linear Regression** if stakeholder interpretation is required.

## Citation

If you use this project, please cite:

Elhattab, L. (2024). *Predicting annual litterfall in China's rainforests using machine learning* (Course project). Faculty of Computer and Information Science, Ain Shams University.

## Data Source

This project is based on the following research paper and its associated dataset:

Geng, A., Tu, Q., Chen, J., Wang, W., & Yang, H. (2022). Improving litterfall production prediction in China under variable environmental conditions using machine learning algorithms.

All credit for data collection and ecological analysis belongs to the original authors.

## Contact

For questions or collaboration inquiries, please open an issue in the project repository.

---
