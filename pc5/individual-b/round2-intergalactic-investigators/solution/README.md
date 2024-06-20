# Intergalactic Investigators

*Solution Guide*

## Overview

Find and retrieve data then cross-reference it with the provided star map to track the locations of five spaceships. There are four possible variants for this challenge. This solution guide covers the walk-through for Variant 1, organized by submission question. The steps used to solve all variants will be similar, but the answers will vary.

We divided the walk-through into two parts: first, we show you how to find and get the data; next, we show you how to plot the data on a map. Variant 1 questions and answers follow. For your convenience, we included the answers to the other variants too.

Before you begin, review the following:

1. **Star map:** The [Elysium_nova_system.png](../challenge/Elysium_Nova_System.png) image shows you what the Elysium Nova System looks like.
2. **Supplemental info:** The [ENS_info.txt](../challenge/ENS_info.txt) file gives you additional information about the star map.

## Part 1: Find and retrieve the data

The challenge document tells you the data is on a host on the `10.1.1.0/24` subnet. Begin by scanning the subnet using the following command:

```bash
    nmap 10.1.1.0/24
```
You should see two hosts. The first is the gateway at `10.1.1.1`, and the second is the one we want. In this example, the host is: `10.1.1.50`. Next, do a port scan of the host using:

```bash
    nmap -p- 10.1.1.50
```

Port `33333` is open. That's your hint that the data might be hosted there. Try to connect and download the data.

```bash
    nc 10.1.1.50 33333
```

You'll get flooded with data. Run the command again, but pipe the information into a new file.

```bash
    nc 10.1.1.50 33333 > data
```

The data consists of two main parts. 
1. The first part is a list of **stars** and a list of **planets** present in the `Elysium_nova_system.png`. 
2. The second part is a huge block of `JSON records` in a list containing information about the five ships. The names of these ships are: *Sina*, *SS Sanji*, *Twilight Brigade*, *Nebuchadnezzar*, and *Xemnas*.


## Part 2: Plot data on map

To answer any questions about the movement of a spaceship across the map, you need to cross-reference the JSON data received against the `Elysium_nova_system.png` map.

In this example, we wrote a script that uses the map as a background and overlays *that* with a scatter plot of the paths the spaceships traveled. 

In order to accomplish this, we used a script to alter the format of the JSON ship data that was received. We took the orignal data format so that it could be represented within a **csv** rather than leave it in plain **json** format. 

In order to do this, we isolated the block of JSON data that was received in the second part above so that it was contained within its own file. Then, replace any single quotes (`'`) in the file to a double-quote (`"`). This is because Python will throws an error message when attempting to read a json if the JSON is formatted with single quotes. This can be achieved by opening the json file in VScode, and then performing a find and replace.

Once those edits have been made, you can run the following code to read the json data and format it so that it can be written to a CSV:

```python
    #!/usr/bin/python3

    import pandas as pd
    import json

    with open('data', 'r') as f:
        data = json.loads(f.read())

    dataset = dict()
    for x in range(len(data)):
        dataset[x] = data[x]

    pd.DataFrame.from_dict(dataset, orient='index').to_csv('dataset.csv', index=False)
```

You should now have the file `dataset.csv` that contains all the records previously received in JSON. 

Running the [solution script](./scripts/visualize.py) against the newly created csv generates a visual of the path taken by each of the ships. 

If done correctly, each ship is represented with a different color; its journeys displayed on the map. Using this visual, assisted by the data in the csv, you can answer the questions. [This](./img/all_ships_paths.png) is what the ship path visual should look like.

If you hover over any of the plotted points, it should show you details regarding that point. This information will be helpful with solving the questions. 

This is what each ship's individual path through the system should look like: 

- [Sina](./img/sina_path_solution.png)
- [SS Sanji](./img/ss_path_solution.png)
- [Twilight Brigade](./img/tb_path_solution.png) 
- [Nebuchadnezzar](./img/neb_ship_solution.png)
- [Xemnas](./img/xemnas_ship_solution.png)

## Variant 1 questions and answers

1. *Name one spaceship that visited Judur during their travel.*

​	**Answer:** `SS Sanji` or ` Twilight Brigade`

2. *During its travel, at which planet or star that it VISITED, did the Sina weigh the most?*

​	**Answer:** `Malo`

3. *Name one planet the Nebuchadnezzar visited during August?*

​	**Answer:** `Wano` or `Landri`

4. *During the SS Sanji travel, between which two planets/stars that they VISITED did the ship have the largest AU (Astronomical Units) traveled?*

​	**Answer:** `Judur` and `Fan-Kui`

## Variant answer quick reference

#### Variant 2

 - Q1: `SS Sanji` or `Xemnas`
 - Q2: `Judur`
 - Q3: `Dokkan` or `Bakyo`
 - Q4: `Xelni II` and ` Wano`

#### Variant 3

 - Q1: `Xemnas` or `Twilight Brigade`
 - Q2: `Morphi`
 - Q3: `Anit` or `Lei-Gong`
 - Q4: `Morphi` and `Namek`

#### Variant 4

 - Q1: `Sina` or `Nebuchadnezzar`
 - Q2: `Anit`
 - Q3: `Kaukai` or `Mahua`
 - Q4: `Trengi` and `Wano`
