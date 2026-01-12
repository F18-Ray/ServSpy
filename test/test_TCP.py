import os
import sys
import subprocess
package_dictionary=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if package_dictionary not in os.sys.path:
    sys.path.insert(0, package_dictionary)
class TestConnect:
    def __init__(self):
        create_tcp_client_amount=int(input())
        self.TCP_server_process=subprocess.Popen(
            ["python", os.path.join(os.path.dirname(__file__), 'test_TCP_server.py')], 
            start_new_session=subprocess.CREATE_NEW_CONSOLE)
        for i in range(create_tcp_client_amount):
            subprocess.Popen(
                ["python", os.path.join(os.path.dirname(__file__), 'test_TCP_client.py')], 
                start_new_session=subprocess.CREATE_NEW_CONSOLE)
if __name__=="__main__":
    TestConnect()
