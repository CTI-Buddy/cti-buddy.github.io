---
layout: default  # Changed from 'page' to ensure footer shows
title: Blog
permalink: /blog/
---

<div class="cyber-main">
  {% for post in site.posts %}
  <article class="post-preview">
    <h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
    <time class="post-date">{{ post.date | date: "%b %-d, %Y" }}</time>
    <div class="post-excerpt">
      {{ post.excerpt | default: post.content | strip_html | truncate: 200 }}
    </div>
  </article>
  {% endfor %}
</div>
