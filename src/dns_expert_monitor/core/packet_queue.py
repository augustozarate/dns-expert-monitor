"""
Secure queue for multi-threaded packet processing
"""
from queue import Queue, Empty
from threading import Thread
import time
from typing import Optional, Callable, Any

class PacketQueue:
    """Thread-safe queue for processing DNS packets"""
    
    def __init__(self, maxsize: int = 1000):
        self.queue = Queue(maxsize=maxsize)
        self.processors = []
        self.running = False
        self.worker_threads = []
        
    def put(self, packet_data: dict):
        """Add a package to the queue"""
        try:
            self.queue.put(packet_data, block=False)
        except:
            # If the queue is full, discard the oldest packet
            try:
                self.queue.get_nowait()  # Discard the oldest
                self.queue.put(packet_data, block=False)
            except:
                pass  # Ignore if you can't
    
    def register_processor(self, processor: Callable[[dict], Any]):
        """Register a processing function"""
        self.processors.append(processor)
    
    def _worker(self):
        """Hilo worker que procesa paquetes"""
        while self.running:
            try:
                packet = self.queue.get(timeout=0.1)
                
                for processor in self.processors:
                    try:
                        processor(packet)
                    except Exception as e:
                        print(f"Processor error: {e}")
                
                self.queue.task_done()
                
            except Empty:
                continue
            except Exception as e:
                print(f"Error in worker: {e}")
    
    def start(self, num_workers: int = 2):
        """Start processing workers"""
        self.running = True
        self.worker_threads = []
        
        for i in range(num_workers):
            worker = Thread(target=self._worker, daemon=True, name=f"PacketWorker-{i}")
            worker.start()
            self.worker_threads.append(worker)
        
        print(f"[✓] Started {num_workers} processing workers")
    
    def stop(self):
        """Stop all workers"""
        self.running = False
        
        for worker in self.worker_threads:
            worker.join(timeout=2)
        
        print("[✓] Workers stopped")
    
    def size(self):
        """Returns the current size of the queue"""
        return self.queue.qsize()
    
    def is_empty(self):
        """Check if the queue is empty"""
        return self.queue.empty()