---
layout: page  # Not 'post' for the blog index
title: Blog
permalink: /blog/
---

<ul class="post-list">
  {% for post in site.posts %}
    <li>
      <h2>
        <a href="{{ post.url }}">{{ post.title }}</a>
      </h2>
      <span class="post-meta">{{ post.date | date: "%b %-d, %Y" }}</span>
    </li>
  {% endfor %}
</ul>
{% for post in site.posts %}
<article class="post-preview">
  <h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
  <time class="post-date">{{ post.date | date: "%b %-d, %Y" }}</time>
  <div class="post-excerpt">
    {{ post.excerpt | default: post.content | strip_html | truncate: 200 }}
  </div>
</article>
{% endfor %}
