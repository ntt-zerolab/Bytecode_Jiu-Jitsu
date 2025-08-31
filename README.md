# Bytecode_Jiu-Jitsu
PoC tools of Bytecode Jiu-Jitsu presented at Black Hat USA 2024 Briefings.

The presentation material is available here:
https://www.blackhat.com/us-24/briefings/schedule/#bytecode-jiu-jitsu-choking-interpreters-to-force-execution-of-malicious-bytecode-38682

The PoC Injector binary we used in the presentation:
https://www.virustotal.com/gui/file/3dd69181f59fbea2f95cb2ccf0d9827dc70f38c844f465abeeeed42c3f12f9f9

The workflow to use our tools for injection:

[Target interpreter] -> Tracer-BJJ -[Trace log]-> STAGER-BJJ -[Interpreter's internal structure]-> Extractor-BJJ -[Extracted bytecode and symbol tables]-> Injector-BJJ

For more information, please see README.md of each tool.

If any abuse of our tools in the wild is identified and action is required, please contact us through the inquiry desk: tos.usui@ntt.com.
We are prepared to discuss measures such as sharing information with security vendors and law enforcement, as well as the potential withdrawal of this repository.
