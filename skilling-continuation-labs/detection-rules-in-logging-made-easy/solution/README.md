# Detection Rules in Logging Made Easy

## Mini-Challenge

Your manager provides you with an additional Security Advisory discussing base64 being decoded and piped to Bash to execute malicious binaries without writing to disk. This method bypasses many traditional detection methods, and your organization wants to ensure they would get alerts.

You have been provided with the command below to test with:

```bash
echo ZWNobyAiSGVsbG8gV29ybGQi | base64 -d | bash
```

Enable a rule that would generate a medium alert when logs with a similar format to the example command are received.

| &#8505; RULE NAMING |
|---|
| Name your rule **Mini-Challenge** if you create your own. |

## Mini-Challenge Solution

1. (**Workstation**) Open Firefox by clicking on the Firefox shortcut in the left launcher.

2. (**Workstation**, **Firefox**) If not already selected, click the "Elastic" browser tab.

3. (**Workstation**, **Firefox**) If prompted, type the username `user` and the password `tartans` to connect to Elastic.

4. (**Workstation**, **Firefox**, **Elastic**) In the upper left, click &#9776; to open a menu.

5. (**Workstation**, **Firefox**, **Elastic**) In the left menu under Security, click **Rules**.

6. (**Workstation**, **Firefox**, **Elastic**) Under "Management" click **Detection rules (SIEM)**.

7. (**Workstation**, **Firefox**, **Elastic**) In the upper right, click **Create new rule**.

8. (**Workstation**, **Firefox**, **Elastic**) Verify that "Custom query" is selected.

9. (**Workstation**, **Firefox**, **Elastic**) Under "Custom query", type a crafted query that would detect the targeted behavior. For example: `process.command_line:*base64 -d* and process.parent.command_line:*bash*`.

10. (**Workstation**, **Firefox**, **Elastic**) Click **Continue**.

11. (**Workstation**, **Firefox**, **Elastic**) Under "About rule" type the name "Mini-Challenge".

    | &#9888; MAKE SURE YOUR RULE NAME MATCHES EXACTLY IN ORDER FOR THE GRADING CHECK TO COMPLETE SUCCESSFULLY! |
    | --- |

12. (**Workstation**, **Firefox**, **Elastic**) Type the description "Detects Base64 Decoded to Interpreter".

13. (**Workstation**, **Firefox**, **Elastic**) Under "Default severity", click the arrow to open the dropdown menu and select "Medium".

14. (**Workstation**, **Firefox**, **Elastic**) Click **Continue**.

15. (**Workstation**, **Firefox**, **Elastic**) Keep the default schedule and click **Continue**.

16. (**Workstation**, **Firefox**, **Elastic**) Click **Create & enable rule**.

17. (**Workstation**) Re-open the Terminal by clicking on the Terminal shortcut in the left launcher.

18. (**Workstation**, **Terminal**) Run the `echo ZWNobyAiSGVsbG8gV29ybGQi | base64 -d | bash` command.

19. (**Workstation**) Return to Elastic by clicking on the Firefox shortcut in the left launcher.

20. (**Workstation**, **Firefox**, **Elastic**) In the upper left, click &#9776; to open a menu.

21. (**Workstation**, **Firefox**, **Elastic**) In the left menu under Security, click **Alerts**.

22. (**Workstation**, **Firefox**, **Elastic**) A Medium severity alert will appear.

    | &#8505; Recall that the rule runs every five (5) minutes. It may take a few minutes for your alert to appear. You may also need to Refresh the page. |
    | --- |

### Alternative Solution:

In Phase 2 of the lab you briefly reviewed predefined rules. One of those rules (covered in Step 6) looked for base64 commands being decoded and sent to an interpreter (**Base64 Decoded Payload Piped to Interpreter**). This rule seems to satisfy what is being requested in the Mini-Challenge. If you enable this rule and run the example command, a medium alert is generated. The grading script is configured to accept this rule and allow the mini-challenge to complete.
