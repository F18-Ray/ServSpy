The TCP Server APIs
===================

TCP Server setup API
--------------------

The TCP Server Setup API is used to create a TCP server. 
The server in the protocal is usually use to connect and 
listen to the TCP clients and handle the data from the 
clients.

.. code-block:: python

    class TCP_Server_Base:
        def __init__(
            self: Self, host: Any, port: Any, max_clients: Any, port_add_step: Any,port_range_num: Any,
            max_file_transfer_thread_num: Any, is_hand_alloc_port: Any, is_input_command_in_console: Any,
            max_custom_workers: Any) -> None: 
            ...

The TCP Server Setup API is defined in the ``TCP_Server_Base`` class.
The parameters of the ``__init__`` method are as follows:

- ``host``: The host IP address to bind the TCP server to.
- ``port``: The port number to bind the TCP server to.
- ``max_clients``: The maximum number of concurrent clients the server can handle.
- ``port_add_step``: The step size for incrementing the port number.
- ``port_range_num``: The number of ports to check in the range.
- ``max_file_transfer_thread_num``: The maximum number of threads for file transfer operations.
- ``is_hand_alloc_port``: A flag indicating whether to manually allocate the port.
- ``is_input_command_in_console``: A flag indicating whether to input commands in the console.
- ``max_custom_workers``: The maximum number of custom worker threads.

Every parameters are all have default values:

- ``host``: Default is ``'127.0.0.1'``
- ``port``: Default is ``65432``
- ``max_clients``: Default is ``10``
- ``port_add_step``: Default is ``1``
- ``port_range_num``: Default is ``100``
- ``max_file_transfer_thread_num``: Default is ``10``
- ``is_hand_alloc_port``: Default is ``False``
- ``is_input_command_in_console``: Default is ``True``
- ``max_custom_workers``: Default is ``10``

The TCP Server Setup API will initialize all the necessary 
parameters and resources for the TCP server.


