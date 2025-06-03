def filter_xml_keywords(
    xml, keywords_list=["/JS", "/JavaScript", "/AA", "/OpenAction"]
):
    result_dict = {}
    for node in xml.getElementsByTagName("Keyword"):
        if node.getAttribute("Name") in keywords_list:
            name = node.getAttribute("Name")
            count = node.getAttribute("Count")
            result_dict[name] = count

    return result_dict
