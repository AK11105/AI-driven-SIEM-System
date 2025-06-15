# Enhanced Performance Evaluation Integration Example
# Add this to the end of your existing main execution code

import sys
sys.path.append('.')  # Add current directory to path
from generate_performance_results import generate_enhanced_performance_results

# =================================================================
# Integration with your existing log anomaly detection system
# =================================================================

def run_enhanced_analysis_integration():
    """
    Example integration with your existing codebase
    Add this function call at the end of your main execution
    """
    
    # Your existing code variables are already available:
    # - ensemble (your trained HybridEnsembleDetector)
    # - single_log_results (from process_single_log_outputs)  
    # - sequential_results (from process_sequential_outputs)
    # - severity_manager (your EnhancedSeverityManager instance)
    # - log_classifier (your RuleBasedLogClassifier instance)
    
    print("\n" + "="*80)
    print("🚀 RUNNING ENHANCED PERFORMANCE ANALYSIS")
    print("="*80)
    
    # Generate comprehensive enhanced results
    enhanced_results = generate_enhanced_performance_results(
        ensemble=ensemble,
        single_results=single_log_results,
        sequential_results=sequential_results,
        severity_manager=severity_manager,
        log_classifier=log_classifier,
        test_loader=test_loader,
        test_data=test_data,
        original_df=original_df,
        train_data=train_data,
        train_loader=train_loader,
        seq_len=SEQ_LEN,
        stride=STRIDE
    )
    
    # Display enhanced analysis summary
    print("\n🎯 ENHANCED ANALYSIS SUMMARY")
    print("-" * 50)
    
    summary = enhanced_results['comprehensive_results']['enhanced_summary']
    
    print("📊 Key Performance Insights:")
    for i, insight in enumerate(summary['key_insights'], 1):
        print(f"   {i}. {insight}")
    
    print(f"\n⚡ Performance Highlights:")
    highlights = summary['performance_highlights']
    print(f"   • Best F1-Score: {highlights['best_f1_score']}")
    print(f"   • Lowest Latency Mode: {highlights['lowest_latency_mode']}")
    print(f"   • Most Efficient Mode: {highlights['most_efficient_mode']}")
    print(f"   • Highest Accuracy Config: {highlights['highest_accuracy_config']}")
    
    print(f"\n💡 Computational Efficiency:")
    efficiency = summary['computational_efficiency']
    print(f"   • Peak Throughput: {efficiency['peak_throughput']}")
    print(f"   • Average Latency: {efficiency['average_latency']}")
    print(f"   • Memory Efficiency: {efficiency['memory_efficiency']}")
    print(f"   • Resource Utilization: {efficiency['resource_utilization']}")
    
    print(f"\n📋 Recommendations:")
    for i, rec in enumerate(summary['recommendations'], 1):
        print(f"   {i}. {rec}")
    
    # Display severity analysis results
    print("\n📊 SEVERITY ANALYSIS ENHANCED RESULTS")
    print("-" * 50)
    
    severity_analysis = enhanced_results['comprehensive_results']['severity_analysis']
    
    # Display threshold effectiveness
    threshold_effectiveness = severity_analysis['threshold_analysis']['threshold_effectiveness']
    print("🎯 Threshold Effectiveness:")
    for percentile, data in threshold_effectiveness.items():
        print(f"   • {percentile}: {data['anomalies_detected']} anomalies "
              f"({data['detection_rate']:.1%} detection rate)")
    
    # Display confidence analysis
    confidence_analysis = severity_analysis['confidence_analysis']
    print("\n🔍 Confidence by Severity Level:")
    for severity, stats in confidence_analysis.items():
        print(f"   • {severity}: Mean={stats['mean']:.3f}, "
              f"Std={stats['std']:.3f}, Count={stats['count']}")
    
    # Display type classification results
    print("\n🏷️ TYPE CLASSIFICATION ENHANCED RESULTS")
    print("-" * 50)
    
    type_analysis = enhanced_results['comprehensive_results']['type_classification']
    
    # Display type distribution
    combined_types = type_analysis['type_statistics']['combined_types']
    print("📈 Anomaly Type Distribution:")
    for anomaly_type, count in sorted(combined_types.items(), key=lambda x: x[1], reverse=True):
        print(f"   • {anomaly_type}: {count} instances")
    
    # Display type-severity correlation
    type_severity_correlation = type_analysis['type_severity_correlation']
    print("\n🔗 Type-Severity Correlations (% High/Critical):")
    for anomaly_type, severity_dist in type_severity_correlation.items():
        high_critical_pct = (severity_dist.get('High', 0) + severity_dist.get('Critical', 0)) * 100
        print(f"   • {anomaly_type}: {high_critical_pct:.1f}%")
    
    # Display computational benchmark results
    print("\n⚡ COMPUTATIONAL BENCHMARK ENHANCED RESULTS")
    print("-" * 50)
    
    computational_analysis = enhanced_results['comprehensive_results']['computational_benchmarks']
    
    # Display throughput analysis
    throughput_data = computational_analysis['throughput_analysis']
    print("🚄 Throughput Analysis:")
    for size_key, data in throughput_data.items():
        size = data['data_size']
        throughput = data['throughput_logs_per_second']
        print(f"   • {size} logs: {throughput:.0f} logs/sec")
    
    # Display latency analysis  
    latency_data = computational_analysis['latency_analysis']
    print("\n⏱️ Latency Analysis (Mean/P95/P99 ms):")
    for mode, batch_data in latency_data.items():
        # Get batch_32 data as representative
        if 'batch_32' in batch_data:
            stats = batch_data['batch_32']
            print(f"   • {mode.capitalize()}: "
                  f"{stats['mean_latency_ms']:.1f}/"
                  f"{stats['p95_latency_ms']:.1f}/"
                  f"{stats['p99_latency_ms']:.1f}")
    
    # Display resource utilization
    resource_util = computational_analysis['resource_utilization']
    print("\n💻 Resource Utilization (Mean %):")
    for mode in ['sequential_mode', 'single_mode', 'hybrid_mode']:
        if mode in resource_util['cpu_utilization']:
            cpu = resource_util['cpu_utilization'][mode]['mean']
            gpu = resource_util['gpu_utilization'][mode]['mean']
            mode_name = mode.replace('_mode', '').capitalize()
            print(f"   • {mode_name}: CPU={cpu:.1f}%, GPU={gpu:.1f}%")
    
    # Display ablation study results
    print("\n🔬 ABLATION STUDY ENHANCED RESULTS")
    print("-" * 50)
    
    ablation_analysis = enhanced_results['comprehensive_results']['ablation_studies']
    
    # Display ensemble benefits
    ensemble_benefits = ablation_analysis['ensemble_vs_single_model']
    ensemble_perf = ensemble_benefits['ensemble_performance']
    improvements = ensemble_benefits['improvement_metrics']
    
    print("🎯 Ensemble vs Individual Models:")
    print(f"   • Ensemble F1-Score: {ensemble_perf['f1_score']:.3f}")
    print(f"   • F1-Score Improvement: {improvements['f1_score']:.1%}")
    print(f"   • Precision Improvement: {improvements['precision']:.1%}")
    print(f"   • Recall Improvement: {improvements['recall']:.1%}")
    
    # Display processing mode comparison
    processing_modes = ablation_analysis['processing_mode_comparison']
    print("\n⚙️ Processing Mode Comparison:")
    for mode, performance in processing_modes.items():
        if isinstance(performance, dict) and 'f1_score' in performance:
            print(f"   • {mode.capitalize()}: F1={performance['f1_score']:.3f}, "
                  f"Latency={performance['processing_time_ms']:.0f}ms")
    
    # Display component importance
    component_analysis = ablation_analysis['architecture_component_analysis']
    print("\n🏗️ Architecture Component Importance:")
    sorted_components = sorted(component_analysis.items(), 
                             key=lambda x: x[1]['impact_score'], reverse=True)
    for component, data in sorted_components[:5]:  # Top 5 components
        print(f"   • {component.replace('_', ' ').title()}: "
              f"Impact={data['impact_score']:.2f}, "
              f"Necessity={data['necessity']}")
    
    # Display hyperparameter sensitivity
    hyperparameter_sensitivity = ablation_analysis['hyperparameter_sensitivity']
    print("\n🎛️ Hyperparameter Sensitivity (Optimal Values):")
    for param, data in hyperparameter_sensitivity.items():
        optimal = data['optimal_value']
        sensitivity = data['sensitivity']
        print(f"   • {param.replace('_', ' ').title()}: {optimal} ({sensitivity} sensitivity)")
    
    # Save visualization data summaries
    print("\n💾 SAVING VISUALIZATION DATA")
    print("-" * 50)
    
    # Save severity visualization summary
    severity_viz = enhanced_results['visualization_data']['severity_analysis']
    with open('enhanced_performance_results/severity_summary.json', 'w') as f:
        json.dump({
            'single_severity_counts': dict(Counter(severity_viz['single_log_severities'])),
            'sequential_severity_counts': dict(Counter(severity_viz['sequential_severities'])),
            'threshold_values': severity_viz['threshold_analysis']['threshold_values'],
            'score_statistics': {
                'single_mean': np.mean(severity_viz['single_log_scores']),
                'sequential_mean': np.mean(severity_viz['sequential_scores']),
                'combined_std': np.std(severity_viz['single_log_scores'] + severity_viz['sequential_scores'])
            }
        }, f, indent=2, default=str)
    
    # Save type classification visualization summary  
    type_viz = enhanced_results['visualization_data']['type_classification']
    with open('enhanced_performance_results/type_classification_summary.json', 'w') as f:
        json.dump({
            'single_type_counts': dict(Counter(type_viz['single_log_types'])),
            'sequential_type_counts': dict(Counter(type_viz['sequential_types'])),
            'type_severity_correlation': type_viz['type_severity_correlation'],
            'most_common_types': list(Counter(type_viz['single_log_types'] + type_viz['sequential_types']).most_common(5))
        }, f, indent=2, default=str)
    
    print("✅ Enhanced analysis complete!")
    print(f"📁 Results saved to enhanced_performance_results/ directory")
    print(f"📊 Generated {len(enhanced_results['comprehensive_results'])} analysis categories")
    print(f"🎯 Check visualization files for chart data")
    
    return enhanced_results

# =================================================================
# Add this to your main execution block
# =================================================================

if __name__ == "__main__":
    # Your existing main code...
    # [All your current code remains the same until the end]
    
    # At the very end, add:
    print(f"\n✅ Standard analysis complete!")
    print(f"🚀 Starting enhanced performance analysis...")
    
    # Run enhanced analysis
    enhanced_results = run_enhanced_analysis_integration()
    
    # Final summary
    print(f"\n🎉 COMPLETE ANALYSIS FINISHED!")
    print(f"📊 Standard Results: single_log_anomalies.json, sequential_anomalies.json")
    print(f"📈 Enhanced Results: enhanced_performance_results/ directory") 
    print(f"🎯 Visualizations: Use chart data from enhanced results")
    print(f"📋 Documentation: All labeled sections ready for insertion")

# =================================================================
# Quick integration instructions:
# =================================================================

"""
INTEGRATION STEPS:

1. Save this file as 'enhanced_integration.py' in your project directory
2. Add this line at the end of your main execution in the original file:
   
   exec(open('enhanced_integration.py').read())

3. Or copy the run_enhanced_analysis_integration() function to your main file
   and call it at the end

4. Run your existing code - it will automatically run enhanced analysis

WHAT YOU GET:

✅ Enhanced severity analysis with:
   - Distribution patterns across processing modes
   - Threshold effectiveness analysis  
   - Confidence correlation studies
   - Advanced statistical metrics

✅ Comprehensive type classification with:
   - Type-severity correlation matrices
   - Pattern effectiveness evaluation
   - Confidence analysis by type
   - Classification accuracy metrics

✅ Advanced computational benchmarks with:
   - Throughput analysis across data sizes
   - Memory profiling and efficiency scores
   - Latency analysis for all processing modes
   - Resource utilization monitoring
   - Scalability coefficient calculation
   - Batch size optimization analysis

✅ Detailed ablation studies with:
   - Ensemble vs single model analysis
   - Processing mode comprehensive comparison
   - Architecture component importance
   - Attention mechanism impact analysis
   - Hyperparameter sensitivity studies
   - Training strategy comparisons

✅ Enhanced visualizations ready for:
   - Severity distribution charts
   - Type classification heatmaps  
   - Computational performance graphs
   - Ablation study comparison charts
   - Resource utilization dashboards

All results are automatically saved to enhanced_performance_results/ 
directory with JSON files ready for visualization and documentation.
"""