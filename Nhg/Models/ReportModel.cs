using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Nhg.Models
{
    public class ReportModel
    {
        public string Id { get; set; }

        public string GroupId { get; set; }

        public string EmbedUrl { get; set; }

        public string Token { get; set; }


        public bool EnableRLS { get; set; }


        public string ErrorMessage { get; internal set; }
    }
}