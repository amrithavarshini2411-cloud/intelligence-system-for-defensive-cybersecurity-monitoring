import threading

approved_requests = {}
lock = threading.Lock()

def mark_approved(request_id):
    with lock:
        approved_requests[request_id] = True

def is_approved(request_id):
    with lock:
        return approved_requests.get(request_id, False)