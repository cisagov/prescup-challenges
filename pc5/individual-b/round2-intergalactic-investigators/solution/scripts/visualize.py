
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import cartopy.crs as ccrs

def visualize():
    # Below command will load the CSV previously created. It is expected that the CSV will be in the same folder as the script.
    df = pd.read_csv('dataset.csv', keep_default_na=False, na_filter=False)
    
    sid_colors = df['ship-id'].astype('category').cat.codes
    # Use categorical codes as colors instead of the 'sid' values
    
    # Below command will load the image to be used as the background. It is expected that the image will be in the same folder as the script.
    img = plt.imread("Elysium_Nova_System.png")

    x_range = 360
    y_ticks = [-180, -135, -90, -45, 0, 45, 90, 135, 180]

    fig, ax = plt.subplots(figsize=(img.shape[1] / 100, img.shape[0] / 100))

    scatter = ax.scatter(
        x='g-long',
        y='g-lat',
        data=df,
        c=sid_colors,
        s=25,
        cmap='gist_rainbow',
        norm=plt.Normalize(0, df['ship-id'].nunique()-1)
        # Use the number of unique SIDs as the color normalization range
    )

    img_extent = [0, x_range, -180, 180]
    ax.imshow(img, zorder=0, extent=img_extent)

    annotations = []
    for index, row in df.iterrows():
        annotation = ax.annotate(
            text='',
            xy=(0, 0),
            ### PLEASE NOTE
            # If you face the issue where the data points pop-up is cut off on the edge, you can edit the `xytext` variable below to shift it.
            # The X value (-20 right now) moves the pop-up left & right. Decrease it to move it left, increase to move it right.
            # The Y value (10 right now)moves the pop-up up & down. Decrease it to move it down, increase to move it up.
            ###
            xytext=(-20,10),
            textcoords="offset points",
            bbox={"boxstyle": "round", "fc": "w"},
            arrowprops={"arrowstyle": "->"}
        )
        annotation.set_visible(False)
        annotations.append(annotation)

    def hover(event):
        for annotation in annotations:
            annotation_visibility = annotation.get_visible()
            if event.inaxes == ax:
                is_contained, annotation_index = scatter.contains(event)
                if is_contained:
                    data_point_location = scatter.get_offsets()[annotation_index['ind'][0]]
                    annotation.xy = data_point_location

                    row = df.iloc[annotation_index['ind'][0]]
                    text_label = row.to_string()
                    annotation.set_text(text_label)

                    annotation.get_bbox_patch().set_facecolor(scatter.to_rgba(sid_colors[annotation_index['ind'][0]]))
                    annotation.set_alpha(0.4)

                    annotation.set_visible(True)
                    fig.canvas.draw_idle()
                else:
                    if annotation_visibility:
                        annotation.set_visible(False)
                        fig.canvas.draw_idle()

    fig.canvas.mpl_connect('motion_notify_event', hover)

    ax.set_xlim(0, x_range)
    ax.set_xticks(np.arange(0, x_range + 1, 40))
    ax.set_xticklabels(np.arange(0, x_range + 1, 40))

    ax.set_ylim(-180, 180)
    ax.set_yticks(y_ticks)
    ax.set_yticklabels(y_ticks)

    ax.set_title("Ship Tracking")
    ax.set_xlabel("Galactic Longitude")
    ax.set_ylabel("Galactic Latitude")

    ax.set_aspect('auto')  # Restore the aspect ratio to the default
    
    # Set the extent of the y-axis to match the desired range
    ax.set_ylim(-180, 180)

    plt.tight_layout()
    plt.show()


if __name__ == '__main__':
    visualize()


