# TCP-R-Trace

This is a small application, which executes tcpdump in the background and
captures its output. The output is then analyzed to identify whole sessions.
They are identified by capturing the SYN packet and waiting for an F or an R
packet.

A sessions is marked as **A**-ctive if still no F or R packets have been
received and as **F**-inished if such are already received.

The duration for a currently active session is defined as the current time minus
the time the SYN packet was received. The duration for an already finished
session is defined as the time of the last packet minus the time of the first
packet.

If a sessions passes a duration threshold specified at the command line using
the **-t** option in seconds (defaults to 2.0) then the whole session is dumped
to an output file specified by the command line option **-o**.

Additional filters could be passed to tcpdump using the **-f** option, but note
that the filter **tcp** is always added to the command line.

The capture interface can be specified using the **-i** option.
