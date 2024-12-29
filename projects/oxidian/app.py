import streamlit as st
import shodan
import os
import asyncio

# Set up the Shodan API
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
api = shodan.Shodan(SHODAN_API_KEY)

# Streamlit app
st.title('Threat Hunting Intelligence Feed')

# Initialize session state for navigation
if 'page' not in st.session_state:
    st.session_state.page = 'search'
if 'selected_result' not in st.session_state:
    st.session_state.selected_result = None
if 'search_results' not in st.session_state:
    st.session_state.search_results = []

def search_shodan(query):
    try:
        results = api.search(query)
        return results
    except shodan.APIError as e:
        st.error(f'Error: {e}')
        return None

def show_search_page():
    # Input for Shodan search query
    query = st.text_input('Enter Shodan search query:', 'apache')

    # Fetch data from Shodan
    if st.button('Search'):
        with st.spinner('Searching Shodan...'):
            results = search_shodan(query)
            if results:
                st.session_state.search_results = results['matches']
                st.session_state.current_page = 0  # Reset page on new search
                st.write(f"Results found: {results['total']}")

    # Filters
    filter_ip = st.text_input("Filter by IP Address")
    filter_port = st.number_input("Filter by Port", min_value=0, step=1, value=None)
    filter_org = st.text_input("Filter by Organization")

    filtered_results = st.session_state.search_results
    if filter_ip:
        filtered_results = [res for res in filtered_results if filter_ip.lower() in res['ip_str'].lower()]
    if filter_port is not None:
        filtered_results = [res for res in filtered_results if res.get('port') == filter_port]
    if filter_org:
        filtered_results = [res for res in filtered_results if filter_org.lower() in res.get('org', '').lower()]

    # Sorting
    sort_by = st.selectbox("Sort by", ["IP", "Port", "Organization"])
    if sort_by == "IP":
        filtered_results.sort(key=lambda x: x['ip_str'])
    elif sort_by == "Port":
        filtered_results.sort(key=lambda x: x.get('port', 0))
    elif sort_by == "Organization":
        filtered_results.sort(key=lambda x: x.get('org', ''))

    # Pagination
    results_per_page = st.slider("Results per page", 10, 50, 20)
    if 'current_page' not in st.session_state:
        st.session_state.current_page = 0

    start_index = st.session_state.current_page * results_per_page
    end_index = start_index + results_per_page
    current_results = filtered_results[start_index:end_index]

    # Display results for the current page
    for i, result in enumerate(current_results):
        st.write('---')
        st.write(f"**IP:** {result['ip_str']}")
        st.write(f"**Organization:** {result.get('org', 'N/A')}")

        if st.button(f"View details for IP: {result['ip_str']}", key=f"details_{i}"):
            st.session_state.page = 'details'
            st.session_state.selected_result = result

    if st.button("Previous Page", disabled=st.session_state.current_page == 0, key="previous_bottom"):
        st.session_state.current_page -= 1
    if st.button("Next Page", disabled=end_index >= len(st.session_state.search_results), key="next_bottom"):
        st.session_state.current_page += 1

def show_details_page():
    result = st.session_state.selected_result
    st.title("System Details")

    if result:
        st.write(f"**IP:** {result['ip_str']}")
        st.write(f"**Organization:** {result.get('org', 'N/A')}")
        st.write(f"**Hostname(s):** {', '.join(result.get('hostnames', ['N/A']))}")
        st.write(f"**ISP:** {result.get('isp', 'N/A')}")
        st.write(f"**ASN:** {result.get('asn', 'N/A')}")
        st.write(f"**Port:** {result.get('port', 'N/A')}")
        st.write(f"**Product:** {result.get('product', 'N/A')}")
        st.write(f"**Operating System:** {result.get('os', 'N/A')}")
        st.write(f"**Transport Protocol:** {result.get('transport', 'N/A')}")
        st.write(f"**Timestamp:** {result.get('timestamp', 'N/A')}")
        location = result.get('location', {})
        st.write(f"**Location:** {location.get('city', 'N/A')}, {location.get('region_code', 'N/A')}, {location.get('country_name', 'N/A')}")
        st.write(f"**Latitude:** {location.get('latitude', 'N/A')}, **Longitude:** {location.get('longitude', 'N/A')}")
        with st.expander("Raw Result Object"):
            st.write(result)
    else:
        st.write("No device details available.")

    if st.button("Back to Search Results"):
        st.session_state.page = 'search'

# Page navigation
query_params = st.query_params
if 'page' in query_params:
    st.session_state.page = query_params['page'][0]

if st.session_state.page == 'search':
    show_search_page()
elif st.session_state.page == 'details':
    show_details_page()
