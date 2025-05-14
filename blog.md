---
layout: page
title: Blog
permalink: /blog/
---

{% for post in site.posts %}
<article class="post-preview">
  <h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
  <small>{{ post.date | date: "%b %-d, %Y" }}</small>
  <p>{{ post.excerpt }}</p>
</article>
{% endfor %}
