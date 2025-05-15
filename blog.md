---
layout: default
title: Blog
---

<h1>Cyber Blog</h1>

{% for post in site.posts %}
  <div class="post-preview">
    <div class="post-date">{{ post.date | date: "%B %d, %Y" }}</div>
    <h2><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h2>
    <div class="post-excerpt">{{ post.excerpt }}</div>
  </div>
{% endfor %}
