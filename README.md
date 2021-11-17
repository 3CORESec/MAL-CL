<p align="center"><img src="./Images/Logo/mal-cl-small.png" width="549" height="500"></p>

# Malicious Command-Line (MAL-CL)

MAL-CL (Malicious Command-Line) aims to collect and document real world and most common "malicious" command-line executions of different tools and utilities while providing actionable detections and resources for the blue team.

# Motivation

The idea for this project stemmed from our analyses of threat intel reports where we were able to identify that, most of the time, threat actor activities were leveraging LOLBINs and "free" tools to perform their actions.

In our analyses it became evident that the same command-line arguments and tools were being used in the majority of adversary activity. With this in mind we decided to document these common use cases and provide actionable context for the blue team.

# Goal

There are two major goals for MAL-CL.

The first is to bring awareness to the abuse of different tools and utilities - used all over the world - by threat actors and malware. The second is to provide a single, central point, that blue teams can use to understand these tools and write better detections.

## Coverage Mind Map

The following MindMap display the tools and utilities currently covered by MAL-CL.

![coverage-mindmap](./Images/MindMaps/MAL-CL-Coverage-MindMap.png)

- 🔍 [Other](./Descriptors/Other)
- 🔍 [Antivirus](./Descriptors/Antivirus)
- 🔍 [Sysinternals](./Descriptors/Sysinternals)
- 🔍 [Windows](./Descriptors/Windows)

## Contributing

If you find a process or a tool that has some command-line options that can or have been (ab)used, please consider contributing them.

- Create a folder with a name of the tool inside one of the available platforms (`Antivirus`, `Sysinternals`, `Windows`, `Other`).
- Inside that folder create a `README.md` (Descriptor) file.

You can use the template available [here](./Template) or simply copy one the already existsting README files and use it as a base. Please follow the same structure and don't remove any titles (all are required).

Looking forward to your awesome contributions.

## Feedback

Found this interesting? Have a question/comment/request? Let us know!

Feel free to open an [issue](https://github.com/3CORESec/MAL-CL/issues) or ping us on [Twitter](https://twitter.com/3CORESec). We also have a [Community Slack](https://launchpass.com/3coresec) where you can discuss our open-source projects, participate in giveaways and have access to projects before they are released to the public.

[![Twitter](https://img.shields.io/twitter/follow/3CORESec.svg?style=social&label=Follow)](https://twitter.com/3CORESec)
