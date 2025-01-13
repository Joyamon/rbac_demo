from django import template

register = template.Library()


@register.filter
def index(indexable, i):
    return indexable[int(i)]


@register.filter
def get_image_url(image):
    return image.get_image_url()
