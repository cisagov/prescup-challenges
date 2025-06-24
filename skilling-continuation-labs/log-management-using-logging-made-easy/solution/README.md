# Solution Guide


## Determine Added Services

1. (**mini-challenge-ubuntu**, **Terminal**) Export a list of services units to a text file.

    ```bash
    sudo systemctl list-unit-files --type=service > /home/user/Desktop/current-services.txt
    ```

2. (**mini-challenge-ubuntu**, **Terminal**) Use `diff` to compare "current-services.txt" to the "fresh-os-services.txt" file.

    ```bash
    user@mini-challenge-ubuntu:~/Desktop$ diff /home/user/Desktop/fresh-os-services.txt /home/user/Desktop/current-services.txt
    14a15
    > auditd.service                             enabled         enabled
    52a54,55
    > elastic-agent.service                      enabled         enabled
    > ElasticEndpoint.service                    enabled         enabled
    85a89
    > mysql.service                              enabled         enabled
    242c246
    < 239 unit files listed.
    ---
    > 243 unit files listed.
    ```

| &#128204; The `mini-challenge-ubuntu` system has had Auditd and MySQL added to it. These are the Elastic integrations you will need to add. |
| --- |


### Create "mini-challenge" Agent Policy With AuditD and MySQL Integrations

1. (**mini-challenge-ubuntu**) Open Firefox by clicking on the Firefox shortcut in the left launcher.

2. (**mini-challenge-ubuntu**, **Firefox**) Enter the URL `https://elastic.skills.hub`

3. (**mini-challenge-ubuntu**, **Firefox**) Enter the username `user` and password `tartans` to connect to Elastic.

4. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) In the upper left, click &#9776; to open a menu.

5. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) In the left menu expand **Management** and click **Fleet**.

6. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **Agent policies**.

7. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **&#8853; Create agent policy**.

8. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Type the name: "mini-challenge".

9. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Leave the "Collect system logs and metrics" box checked and click **Create agent policy**.

10. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click the **mini-challenge** text.

11. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **&#8853; Add integration**.

12. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Use the search bar to locate the "Auditd Logs" integration.

13. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click the "Auditd Logs" integration to select it.

14. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **&#8853; Add Auditd Logs**.

15. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Scroll to the bottom of the "Add Auditd Logs integration" page. In the "Agent Policy" dropdown select "mini-challenge" if it is not already selected.

16. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **&#128427; Save and continue**.

17. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) In the pop-up window, click **Add Elastic Agent later**.

18. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **&#8853; Add integration**.

19. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Use the search bar to locate the "MySQL" integration.

| &#128204; Select the MySQL Integration with the description: "Collect logs and metrics from MySQL servers with Elastic Agent." |
| --- |

20. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **MySQL** integration to select it.

21. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **&#8853; Add MySQL**.

22. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Scroll to the bottom of the "Add MySQL integration" page. In the "Agent Policy" dropdown select "mini-challenge" if it is not already selected.

23. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **&#128427; Save and continue**.

24. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) In the pop-up window, click **Add Elastic Agent later**.

25. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **View all agent policies** to return to the Agent policies page.

26. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **Agents** from the menu bar.

27. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) In the actions column, click &#8943; on the mini-challenge-ubuntu agent row.

28. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) From the "Actions" dropdown menu, select **&#x1F589; Assign to new policy**.

29. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) In the "Agent policy" dropdown menu, select "mini-challenge".

30. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **Assign policy**.


### Create "mc-ilm" Index Lifecycle Management Policy

| &#128204; RECALL THE LOG RETENTION REQUIREMENTS |
| --- |
| - Data is kept in the hot phase for fourteen (14) days.<br> - Logs move to the warm phase after fourteen (14) days.<br> - Logs need to be kept for 120 days before being deleted. |

1. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) In the upper left, click &#9776; to open a menu.

2. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Under Management click **Stack Management**.

3. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **Index Lifecycle Policies**.

4. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) If not already, slide the toggle to "Include managed system policies".

5. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) In the search bar type "logs@lifecycle".

6. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **logs@lifecycle**.

7. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Slide the toggle to enable **Save as new policy**.

8. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Change the policy name to "mc-ilm".

9. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Slide the toggle to enable "Warm phase".

10. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) In the box following "Move data into phase when:", type "14" and make sure days is selected.

11. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click the trash icon. The text will change to "Delete data after this phase".

12. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Scroll down to the "Delete Phase".

13. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) In the box following "Move data into phase when:", type "120" and make sure days is selected.

14. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **Save as new policy**.


### Apply Index Lifecycle Management Policy to Logs

1. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) In the upper left, click &#9776; to open a menu.

2. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) In the left menu click **Management**.

3. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **Index Management**.

4. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **Component Templates**.

5. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **Create component template**.

6. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Type the name "logs@custom".

7. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **Next**.

8. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Apply the ILM Policy to the lifecycle policy by pasting the configuration below into the Index settings box.

    ```json
    {
        "index": {
            "lifecycle": {
                "name": "mc-ilm"
            }
        }
    }
    ```

| &#9888; NOTE |
|---|
| When copying into the virtual machine console, extra spaces or tabs can be inserted. Make sure to remove these spaces so your configuration matches. |

9. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **Next** until you reach the final "Review" page.

10. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **Create component template**.

11. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) In the summary, verify that "logs@custom" is being used by "logs".

12. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Close the summary.

13. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **Index Templates**.

14. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Use the search bar to locate the "logs" index template.

15. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **logs**.

16. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Click **Preview**.

17. (**mini-challenge-ubuntu**, **Firefox**, **Elastic**) Verify the "mc-ilm" index lifecycle is applied.