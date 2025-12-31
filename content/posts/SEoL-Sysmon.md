+++
date = '2026-12-29T10:08:29-05:00'
draft = false
title = 'Cleaning SEoL dotnet Frameworks with Sysmon'
[build]
	list = 'always'
+++

The problem: We need to remove a great many unsupported .Net Core frameworks from  the fleet, but we have no idea what's using them.  And randomly breaking things isn't an option.

At a high level, we deployed Sysmon to every PC that had a dotnet runtime, with a configuration that detected dll loads from .net directories.  This was paired with a scheduled task that fired every time an event was written to the Sysmon log, converting it to a file.  

We then collected these events to a central location, and recorded what apps were using the outdated .net frameworks.  We made device collections for each app installed, and used those to exclude the the devices from the final removal collection.

Once we had accumulated enough usage data that we were confident that there were no surprise applications, we deployed the uninstaller.  The initial uninstaller used the dotnet uninstall tool, but this failed to actually remove things.  A second tool that used PSAppDeployToolkit to remove the runtimes worked much better.