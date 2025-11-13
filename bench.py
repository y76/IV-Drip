import subprocess
import time
import sys
import signal
import os

def benchmark(num_brokers=500, num_pii=10):
    
    processes = []
    print(num_brokers, num_pii)
    setup = "python setup.py " + str(num_brokers)
    os.system(setup)
    time.sleep(0.2)

    f= open('exTimes.csv', 'a')
    toAppend = str(num_brokers) + "," + str(num_pii) +","
    f.write(toAppend)
    f.close()

    try:
    
        # Broker
        print("\n broker.py.")
        broker_process = subprocess.Popen(
            [sys.executable, "broker.py",str(num_brokers), str(num_pii)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        processes.append(("broker", broker_process))
        # time.sleep(1)
        
        # Start intermediary
        print("intermediary.py")
        intermediary_process = subprocess.Popen(
            [sys.executable, "intermediary.py",str(num_brokers), str(num_pii)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        processes.append(("intermediary", intermediary_process))
        # time.sleep(1)
        
        # Start consumer
        print("consumer.py")
        consumer_process = subprocess.Popen(
            [sys.executable, "consumer.py",str(num_brokers), str(num_pii)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        processes.append(("consumer", consumer_process))
        
        # Wait for all processes to complete
        for name, process in processes:
            stdout, stderr = process.communicate()
            
            print(f"\n{'=' * 60}")
            print(f"{name.upper()} OUTPUT:")
            print('=' * 60)
            if stdout:
                print(stdout)
            if stderr:
                print(f"ERRORS:\n{stderr}")

        
    except KeyboardInterrupt:
        for name, process in processes:
            process.kill()
        sys.exit(1)
    
    except Exception as e:
        for name, process in processes:
            process.kill()
        sys.exit(1)

def benchmarks(num_runs=5, num_brokers=500, num_pii=10):
    print(f"\nRunning {num_runs} benchmark iterations.")
    
    ##
    # Here create csv file

    for i in range(num_runs):
        print(f"\n{'@' * 60}")
        print(f"RUN {i+1}/{num_runs}")
        
        benchmark(num_brokers, num_pii)
        if i < num_runs - 1:
            time.sleep(1)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Benchmark IVDrip protocol')
    parser.add_argument('-n', '--num-runs', type=int, default=1, 
                        help='Number of benchmark runs (default: 1)')
    parser.add_argument('-b', '--num-brokers', type=int, default=500, 
                        help='Number of brokers (default: 500)')
    parser.add_argument('-p', '--num-pii', type=int, default=30, 
                        help='Number of PII elements per broker (default: 10, max: 30)')
    
    args = parser.parse_args()
    
    benchmarks(args.num_runs, args.num_brokers, args.num_pii)